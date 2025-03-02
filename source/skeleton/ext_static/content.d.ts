type FormInfo = {
    form: HTMLFormElement,
    searchedForUser: boolean,
    userInput: HTMLInputElement | null,
    passwordInput: HTMLInputElement | null,
};

type Message =
    { type: "fill_user_password", user: string, password: string } |
    { type: "fill_field", text: string };