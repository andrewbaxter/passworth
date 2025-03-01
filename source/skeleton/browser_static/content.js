importScripts('./wasm/pkg/content2.js');
browser.runtime.onInstalled.addListener(() => (async () => {
    await wasm_bindgen('./wasm/pkg/content2_bg.wasm');
    wasm_bindgen.main();
})());
