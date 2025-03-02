/// <reference path="content.d.ts" />

/** @type {HTMLInputElement?} */
var lastFocus = null;

document.body.addEventListener("focus", ev => {
    if (ev.target instanceof HTMLInputElement) {
        lastFocus = ev.target;
    }
}, { capture: true });
browser.runtime.onMessage.addListener((message0, _, responder) => {
    try {
        responder(null);
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
                        for (const [selType, sel] of
                            userSels.map(
                                s =>
                                    /** @type {["user"|"password", string]} */
                                    (["user", s])
                            ).concat(
                                passwordSels.map(s => ["password", s]),
                            )) {
                            const anchorElements = document.querySelectorAll(sel);
                            const seenForms = new Set();
                            for (const anchorElement0 of anchorElements) {
                                const anchorElement =
                                    /** @type {HTMLInputElement?} */
                                    (anchorElement0);

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
                        return;

                    } while (false);

                    // Found form but didn't find all elements yet, search for missing element.
                    // Proceed even if missing (for e.g. when username + password are on separate pages...)
                    passwordInput = selectedForm.passwordInput;
                    if (selectedForm.searchedForUser) {
                        userInput = selectedForm.userInput;
                    } else {
                        for (const sel of userSels) {
                            const found = document.evaluate(sel, selectedForm.form).iterateNext();
                            if (found) {
                                userInput = /** @type {HTMLInputElement?} */ (found);
                                break;
                            }
                        }
                    }

                } while (false);

                if (userInput) {
                    userInput.value = message.user;
                    console.log("Passworth: set value on user", userInput)
                } else {
                    console.log("Passworth: no user input found")
                }
                if (passwordInput) {
                    passwordInput.value = message.password;
                    console.log("Passworth: set value on password", passwordInput)
                } else {
                    console.log("Passworth: no user password found")
                }

                break;

            case "fill_field":
                if (lastFocus != null) {
                    lastFocus.value = message.text;
                    console.log("Passworth: set value on element", lastFocus)
                } else {
                    console.log("Passworth: no focus found")
                }

                break;

            default:
                throw ["Invalid message type", message];
        }
    } catch (e) {
        console.log("Passworth: Error processing message", e)
    }
});