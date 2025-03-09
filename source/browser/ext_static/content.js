/// <reference path="content.d.ts" />

// From browserpass (nearly verbatim)
// ============================================================================

/**
 * 
 * @param {Document|Element} parent Element to search under
 * @param {string[]} selectors List of input elem selectors
 * @param {string[]?} allowedInputTypes Allowed type= for input elements
 * @returns 
 */
const queryAllVisible = (parent, selectors, allowedInputTypes) => {
    const result = [];
    for (const sel of selectors) {
        for (const elem0 of parent.querySelectorAll(sel)) {
            const elem = /** @type {HTMLInputElement} */ (elem0);

            // Ignore disabled fields
            if (elem.disabled) {
                continue;
            }
            // Elem or its parent has a style 'display: none',
            // or it is just too narrow to be a real field (a trap for spammers?).
            if (elem.offsetWidth < 30 || elem.offsetHeight < 10) {
                continue;
            }
            // We may have a whitelist of acceptable field types. If so, skip elements of a different type.
            if (allowedInputTypes && allowedInputTypes.indexOf(elem.type.toLowerCase()) < 0) {
                continue;
            }
            // Elem takes space on the screen, but it or its parent is hidden with a visibility style.
            let style = window.getComputedStyle(elem);
            if (style.visibility == "hidden") {
                continue;
            }
            // Elem is outside of the boundaries of the visible viewport.
            let rect = elem.getBoundingClientRect();
            if (
                rect.x + rect.width < 0 ||
                rect.y + rect.height < 0 ||
                rect.x > window.innerWidth ||
                rect.y > window.innerHeight
            ) {
                continue;
            }
            // Elem is hidden by its or or its parent's opacity rules
            const OPACITY_LIMIT = 0.1;
            let opacity = 1;
            for (
                let testElem = /** @type {HTMLElement} */ (elem);
                opacity >= OPACITY_LIMIT && testElem && testElem.nodeType === Node.ELEMENT_NODE;
                testElem = testElem.parentElement
            ) {
                let style = window.getComputedStyle(testElem);
                if (style.opacity) {
                    opacity *= parseFloat(style.opacity);
                }
            }
            if (opacity < OPACITY_LIMIT) {
                continue;
            }
            // This element is visible, will use it.
            result.push(elem);
        }
    }
    return result;
};

// ============================================================================

/** @type {HTMLInputElement?} */
var lastFocus = null;

document.body.addEventListener("focus", ev => {
    if (ev.target instanceof HTMLInputElement) {
        lastFocus = ev.target;
    }
}, { capture: true });
document.body.addEventListener("blur", ev => {
    if (ev.target instanceof HTMLInputElement) {
        lastFocus = ev.target;
    }
}, { capture: true });

/**
 * @param {HTMLInputElement} el0 
 * @param {string} value 
 */
const setInputValue = (el0, value) => {
    let el = el0;

    // Trigger focus handler
    for (const eventName of ["click", "focus"]) {
        el.dispatchEvent(new Event(eventName, { bubbles: true }));
    }

    // Some sites replace the element with a new element when you click?
    const elBounds = el.getBoundingClientRect();
    const topEl = document.elementFromPoint(
        window.scrollX + elBounds.x + elBounds.width / 2.,
        window.scrollY + elBounds.y + elBounds.height / 2.,
    );
    if (topEl != el && topEl instanceof HTMLInputElement) {
        el = topEl;
        for (let eventName of ["click", "focus"]) {
            el.dispatchEvent(new Event(eventName, { bubbles: true }));
        }
    }

    // Trigger more event handlers in case something does something weird
    for (const eventName of ["keydown", "keypress", "keyup", "input", "change"]) {
        el.dispatchEvent(new Event(eventName, { bubbles: true }));
    }

    // Do the deed
    if (el.maxLength > 0) {
        value = value.substring(0, el.maxLength);
    }
    const initialValue = el.value || el.getAttribute("value");
    el.setAttribute("value", value);
    el.value = value;

    // Trigger post-edit handlers
    for (let eventName of ["keydown", "keypress", "keyup", "input", "change"]) {
        el.dispatchEvent(new Event(eventName, { bubbles: true }));
    }

    // Sometimes post-edit handlers sabotage the contents (browserpass's words), so do it again
    if (el.value === initialValue) {
        el.setAttribute("value", value);
        el.value = value;
    }

    // Trigger unfocus handlers
    el.dispatchEvent(new Event("blur", { bubbles: true }));
};

browser.runtime.onMessage.addListener((message0, _, responder) => {
    try {
        const message = /** @type {Message} */(message0);
        switch (message.type) {
            case "fill_user_password":
                /** @type {string[]} */
                const userSels = [
                    "input[autocomplete=username i]",
                    "input[name=login i]",
                    "input[name=user i]",
                    "input[name=username i]",
                    "input[name=email i]",
                    "input[name=alias i]",
                    "input[id=login i]",
                    "input[id=user i]",
                    "input[id=username i]",
                    "input[id=email i]",
                    "input[id=alias i]",
                    "input[class=login i]",
                    "input[class=user i]",
                    "input[class=username i]",
                    "input[class=email i]",
                    "input[class=alias i]",
                    "input[name*=login i]",
                    "input[name*=user i]",
                    "input[name*=email i]",
                    "input[name*=alias i]",
                    "input[id*=login i]",
                    "input[id*=user i]",
                    "input[id*=email i]",
                    "input[id*=alias i]",
                    "input[class*=login i]",
                    "input[class*=user i]",
                    "input[class*=email i]",
                    "input[class*=alias i]",
                    "input[type=email i]",
                    "input[autocomplete=email i]",
                    "input[type=text i]",
                    "input[type=tel i]",
                ];
                const userAllowedInputTypes = ["text", "tel", "email"];
                /** @type {string[]} */
                const passwordSels = ["input[type=password i][autocomplete=current-password i]", "input[type=password i]"];

                /** @type {HTMLInputElement?} */
                let userInput;
                /** @type {HTMLInputElement?} */
                let passwordInput;
                SELECTED_INPUTS: do {

                    /** @type {FormInfo} */
                    let selectedForm;
                    SELECTED_FORM: do {

                        const classifiedForms =
                            /** @type { Map<boolean, Map<boolean, FormInfo[]>> } */
                            (new Map());

                        // Find and classify forms by likelihood to be a login form (form markers, has password element, etc)
                        //
                        // Start with passwords because I think those are less ambiguously labeled.
                        const anchorElementsPwFirst = queryAllVisible(document, passwordSels, null).map(s =>
                            /** @type {["user"|"password", HTMLInputElement]} */
                            (["password", s])
                        ).concat(
                            queryAllVisible(document, userSels, userAllowedInputTypes).map(
                                s =>
                                    /** @type {["user"|"password", HTMLInputElement]} */
                                    (["user", s])
                            ));
                        const seenForms = new Set();
                        for (const [selType, anchorElement] of anchorElementsPwFirst) {
                            const form = anchorElement.form;
                            if (!form) {
                                continue;
                            }
                            if (seenForms.has(form)) {
                                continue;
                            }
                            seenForms.add(form);

                            const hasMark = (() => {
                                for (const attr in ["id", "name", "class", "action"]) {
                                    for (const wantValue in [
                                        "login",
                                        "log-in",
                                        "log_in",
                                        "signin",
                                        "sign-in",
                                        "sign_in",
                                    ]) {
                                        const haveValue = form.getAttribute(attr);
                                        if (!haveValue) {
                                            continue;
                                        }
                                        if (haveValue.toLowerCase() != wantValue) {
                                            continue;
                                        }
                                        return true;
                                    }
                                }
                                return false;
                            })();

                            const passwordInput0 = (
                                /** @type {()=>HTMLInputElement?} */
                                () => {
                                    if (anchorElement.type == "password") {
                                        return anchorElement;
                                    }
                                    for (const sel of passwordSels) {
                                        const found = form.querySelectorAll(sel)[Symbol.iterator]().next().value;
                                        if (found) {
                                            return /** @type {HTMLInputElement} */ (found);
                                        }
                                    }
                                    return null;
                                })();
                            const hasPassword = !!passwordInput0;

                            const candidateForm = {
                                form: form,
                                searchedForUser: selType == "user",
                                userInput: selType == "user" ? anchorElement : null,
                                passwordInput: passwordInput0,
                            };

                            // Short-circuit search for (near-)perfect matches
                            if (hasMark && hasPassword) {
                                if (selType == "user") {
                                    // Perfect match, exit search
                                    userInput = anchorElement;
                                    passwordInput = passwordInput0;
                                    break SELECTED_INPUTS;
                                } else {
                                    // Perfect enough, but need to find other input
                                    selectedForm = candidateForm;
                                    break SELECTED_FORM;
                                }
                            }

                            // Oof... https://github.com/microsoft/TypeScript/issues/27387
                            /** @type {Map<boolean, FormInfo[]>} */
                            var classifiedForms1;
                            if (classifiedForms.has(hasMark)) {
                                classifiedForms1 = classifiedForms.get(hasMark);
                            } else {
                                classifiedForms1 = new Map();
                                classifiedForms.set(hasMark, classifiedForms1);
                            }
                            /** @type {FormInfo[]} */
                            var classifiedForms2;
                            if (classifiedForms1.has(hasPassword)) {
                                classifiedForms2 = classifiedForms1.get(hasPassword);
                            } else {
                                classifiedForms2 = [];
                                classifiedForms1.set(hasPassword, classifiedForms2);
                            }
                            classifiedForms2.push(candidateForm);
                        }

                        // Select the best form by criteria
                        for (const wantMark of [true, false]) {
                            for (const wantPassword of [true, false]) {
                                /** @type {Map<boolean, FormInfo[]>} */
                                var classifiedForms1;
                                if (classifiedForms.has(wantMark)) {
                                    classifiedForms1 = classifiedForms.get(wantMark);
                                } else {
                                    classifiedForms1 = new Map();
                                    classifiedForms.set(wantMark, classifiedForms1);
                                }
                                /** @type {FormInfo[]} */
                                var classifiedForms2;
                                if (classifiedForms1.has(wantPassword)) {
                                    classifiedForms2 = classifiedForms1.get(wantPassword);
                                } else {
                                    classifiedForms2 = [];
                                    classifiedForms1.set(wantPassword, classifiedForms2);
                                }
                                for (const formInfo of classifiedForms2) {
                                    selectedForm = formInfo;
                                    break SELECTED_FORM;
                                }
                            }
                        }

                        // No match, abort
                        throw "Couldn't find anything that looks like a login form";

                    } while (false);

                    // Found form but didn't find all elements yet, search for missing element.
                    // Proceed even if missing (for e.g. when username + password are on separate pages...)
                    passwordInput = selectedForm.passwordInput;
                    if (selectedForm.searchedForUser) {
                        userInput = selectedForm.userInput;
                    } else {
                        for (const found of queryAllVisible(selectedForm.form, userSels, userAllowedInputTypes)) {
                            if (found == passwordInput) {
                                continue;
                            }
                            userInput = found;
                        }
                    }

                } while (false);

                if (userInput) {
                    setInputValue(userInput, message.user);
                    console.log("Passworth: set value on user", userInput)
                } else {
                    console.log("Passworth: no user input found")
                }
                if (passwordInput) {
                    setInputValue(passwordInput, message.password);
                    console.log("Passworth: set value on password", passwordInput)
                } else {
                    console.log("Passworth: no user password found")
                }

                break;

            case "fill_field":
                if (lastFocus == null) {
                    throw "No focused inputs in history";
                }
                console.log("Passworth: set value on element", lastFocus)
                setInputValue(lastFocus, message.text);

                break;

            default:
                throw ["Invalid message type", message];
        }
        responder(null);
    } catch (e) {
        responder(`${e}`);
    }
});