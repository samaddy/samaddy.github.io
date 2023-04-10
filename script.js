const cipherBtn = document.getElementById("cipher-btn");
const cipherInput = document.getElementById("cipher-input");
const cipherText = document.querySelector(".cipher-text");


cipherBtn.addEventListener("click", function (event) {
    const userInput = cipherInput.value.trim();

    if (!userInput) {
        return;
    }

    if (userInput.toLowerCase() === "knowledge is power") {
        cipherText.innerHTML = "That is Correct!";
        event.preventDefault();


        const duration = 2 * 1000;
        const end = Date.now() + duration;

        (function frame() {
            confetti({
                particleCount: 100,
                startVelocity: 30,
                spread: 360,
                origin: {
                    x: Math.random(),
                    y: Math.random()
                }
            });

            // keep going until we are out of time
            if (Date.now() < end) {
                requestAnimationFrame(frame);
            }
        }());

        setTimeout(function () {
            cipherText.innerHTML = "Sfnfou Pm Tifwf";
        }, 5000)
    }

    else {
        cipherText.innerHTML = "Incorrect answer, try again.";
        setTimeout(function () {
            cipherText.innerHTML = "Sfnfou Pm Tifwf";
        }, 3000)
    }

    cipherInput.value = '';
});