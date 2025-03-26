type HasForm = boolean;
type HasFormMark = boolean;
type HasPassword = boolean;

type FormInfo = {
    // A ShadowRoot is basically the same as a form, right reddit?
    form: HTMLFormElement | null,
    searchedForUser: boolean,
    userInput: HTMLInputElement | null,
    passwordInput: HTMLInputElement | null,
};

type Message =
    { type: "fill_user_password", user: string, password: string } |
    { type: "fill_field", text: string };
