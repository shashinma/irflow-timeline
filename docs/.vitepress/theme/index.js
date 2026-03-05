import DefaultTheme from 'vitepress/theme'
import './custom.css'
import CustomLayout from './CustomLayout.vue'
import InteractiveDemo from './InteractiveDemo.vue'

export default {
  extends: DefaultTheme,
  Layout: CustomLayout,
  enhanceApp({ app }) {
    app.component('InteractiveDemo', InteractiveDemo)
  },
}
