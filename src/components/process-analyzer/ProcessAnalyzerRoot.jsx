import useUIStore from "../../store/useUIStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import ProcessAnalyzerProvider from "./ProcessAnalyzerProvider.jsx";
import ProcessTreeModal from "./internals/ProcessTreeModal.jsx";

export default function ProcessAnalyzerRoot({ activeFilters }) {
  const modal = useUIStore((s) => s.modal);
  const ct = useCurrentTab();
  return (
    <ProcessAnalyzerProvider activeFilters={activeFilters}>
      {modal?.type === "processTree" && ct && <ProcessTreeModal />}
    </ProcessAnalyzerProvider>
  );
}
