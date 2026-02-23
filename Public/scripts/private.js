const updateKVForm = document.getElementById("updateKVForm");

updateKVForm.addEventListener("submit", async function(event) {
    event.preventDefault();

    const key = document.getElementById("key").value;
    const value = document.getElementById("value").value;

    const response = await fetch("/update", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({key, value})
    })
    
    console.log(response);
});
