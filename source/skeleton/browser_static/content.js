/*
importScripts('./content2.js');
browser.runtime.onInstalled.addListener(() => (async () => {
    await wasm_bindgen('./content2_bg.wasm');
    wasm_bindgen.main();
})());
*/
import init from "./content2.js";
init("./content2_bg.wasm");