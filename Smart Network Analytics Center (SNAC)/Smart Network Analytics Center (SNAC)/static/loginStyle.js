const email = document.getElementById("email");
const password = document.getElementById("password");
const loginBtn = document.getElementById("loginBtn");
const loginMessage = document.getElementById("loginMessage");

loginBtn.addEventListener("click", async () => {
    loginMessage.innerText = "";

    if (email.value === "" || password.value === "") {
        loginMessage.innerText = "Please fill all fields";
        return;
    }

    loginBtn.disabled = true;

    try {
        const response = await fetch("/api/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                email: email.value,
                password: password.value
            })
        });

        const data = await response.json();

        if (!response.ok) {
            loginMessage.innerText = data.message || "Login failed";
            return;
        }

        window.location.href = data.redirect || "/dashboard";
    } catch (error) {
        loginMessage.innerText = "Unable to reach server";
    } finally {
        loginBtn.disabled = false;
    }
});
