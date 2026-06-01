const path = require("path");
const { Worker } = require("worker_threads");

class JobManager {
  constructor({ safeSend, dbg }) {
    this.safeSend = safeSend || (() => {});
    this.dbg = dbg || (() => {});
    this.jobs = new Map();
    this.counter = 0;
  }

  startWorkerJob({ type, worker, workerData = {}, channels = {}, metadata = {} }) {
    const jobId = workerData.jobId || `${type || "job"}_${++this.counter}_${Date.now()}`;
    const startedAt = Date.now();
    const workerPath = path.isAbsolute(worker) ? worker : path.join(__dirname, worker);

    const job = {
      id: jobId,
      type,
      status: "running",
      startedAt,
      updatedAt: startedAt,
      metadata,
      worker: null,
      result: null,
      error: null,
    };
    this.jobs.set(jobId, job);

    const thread = new Worker(workerPath, {
      workerData: { ...workerData, jobId, type },
    });
    job.worker = thread;

    this._emitJob(job, { phase: "started", progress: 0 });

    const promise = new Promise((resolve, reject) => {
      thread.on("message", (message = {}) => {
        if (message.type === "progress") {
          const normalizedProgress = this._normalizeProgress(job, message.progress || {});
          job.updatedAt = Date.now();
          this._emitJob(job, normalizedProgress);
          if (channels.progress) this.safeSend(channels.progress, normalizedProgress);
          return;
        }

        if (message.type === "event" && message.channel) {
          this.safeSend(message.channel, message.payload);
          return;
        }

        if (message.type === "result") {
          job.status = "completed";
          job.updatedAt = Date.now();
          job.result = message.result;
          this._emitJob(job, { phase: "completed", progress: 100, done: true });
          if (channels.complete) this.safeSend(channels.complete, message.result);
          resolve(message.result);
        }
      });

      thread.on("error", (err) => {
        job.status = job.status === "cancelling" ? "cancelled" : "failed";
        job.updatedAt = Date.now();
        job.error = err?.message || String(err);
        this._emitJob(job, { phase: job.status, error: job.error, done: true });
        reject(err);
      });

      thread.on("exit", (code) => {
        job.worker = null;
        if (job.status === "completed" || job.status === "failed" || job.status === "cancelled") return;
        if (job.status === "cancelling" || code === 1) {
          job.status = "cancelled";
          job.updatedAt = Date.now();
          this._emitJob(job, { phase: "cancelled", done: true });
          const err = new Error("Job cancelled");
          err.cancelled = true;
          reject(err);
          return;
        }
        if (code !== 0) {
          job.status = "failed";
          job.updatedAt = Date.now();
          job.error = `Worker exited with code ${code}`;
          this._emitJob(job, { phase: "failed", error: job.error, done: true });
          reject(new Error(job.error));
        }
      });
    }).finally(() => {
      setTimeout(() => this._prune(), 10 * 60 * 1000).unref?.();
    });

    job.promise = promise;
    return { jobId, promise };
  }

  cancel(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) return { ok: false, error: "Job not found" };
    if (!job.worker || job.status !== "running") return { ok: false, status: job.status };
    job.status = "cancelling";
    job.updatedAt = Date.now();
    this._emitJob(job, { phase: "cancelling" });
    try { job.worker.postMessage({ type: "cancel" }); } catch {}
    setTimeout(() => {
      if (job.worker && job.status === "cancelling") {
        try { job.worker.terminate(); } catch {}
      }
    }, 250).unref?.();
    return { ok: true };
  }

  cancelWhere(predicate) {
    let cancelled = 0;
    for (const job of this.jobs.values()) {
      if (!predicate(job)) continue;
      const result = this.cancel(job.id);
      if (result.ok) cancelled++;
    }
    return cancelled;
  }

  terminateAll() {
    for (const job of this.jobs.values()) {
      if (!job.worker) continue;
      job.status = "cancelled";
      job.updatedAt = Date.now();
      try { job.worker.terminate(); } catch {}
    }
  }

  list() {
    return [...this.jobs.values()].map((job) => this._serialize(job));
  }

  _emitJob(job, progress = {}) {
    const normalizedProgress = this._normalizeProgress(job, progress);
    const payload = {
      job: this._serialize(job),
      progress: {
        jobId: job.id,
        type: job.type,
        ...normalizedProgress,
      },
    };
    try { this.safeSend("job-progress", payload); } catch {}
  }

  _normalizeProgress(job, progress = {}) {
    const metadata = job?.metadata || {};
    return {
      ...(metadata.tabId && !progress.tabId ? { tabId: metadata.tabId } : null),
      ...(metadata.fileName && !progress.fileName ? { fileName: metadata.fileName } : null),
      ...progress,
    };
  }

  _serialize(job) {
    return {
      id: job.id,
      type: job.type,
      status: job.status,
      startedAt: job.startedAt,
      updatedAt: job.updatedAt,
      metadata: job.metadata,
      error: job.error,
    };
  }

  _prune() {
    const cutoff = Date.now() - 10 * 60 * 1000;
    for (const [id, job] of this.jobs) {
      if (job.worker) continue;
      if (job.updatedAt < cutoff) this.jobs.delete(id);
    }
  }
}

module.exports = { JobManager };
