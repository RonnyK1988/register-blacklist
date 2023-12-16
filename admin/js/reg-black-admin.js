document.addEventListener('DOMContentLoaded', function () {

    // Set the "Domains" tab as active initially
    const initialTab = document.querySelector('.nav-tab[href="#tab-domains"]');
    initialTab.classList.add('nav-tab-active');

    // Add click event listeners to toggle tab visibility
    const tabs = document.querySelectorAll('.nav-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', handleTabClick);
    });

    // Add click event listeners to delete links
    const deleteLinks = document.querySelectorAll(".delete-link");
    deleteLinks.forEach(link => {
        link.addEventListener("click", handleDeleteClick);
    });

    function handleTabClick(event) {
        event.preventDefault();

        const targetId = event.target.getAttribute('href').substr(1);

        tabs.forEach(navTab => navTab.classList.remove('nav-tab-active'));
        event.target.classList.add('nav-tab-active');

        const tabContents = document.querySelectorAll('#tab-domains, #tab-emails, #tab-settings, #tab-statistics');
        tabContents.forEach(tabContent => {
            tabContent.style.display = tabContent.id === targetId ? 'block' : 'none';
        });
    }

    async function handleDeleteClick(event) {
        event.preventDefault();

        const type = this.getAttribute("data-type");
        const value = this.getAttribute("data-value");

        if (await confirmDelete(type)) {
            try {
                const nonce = document.querySelector("#reg-black-nonce").value;
                const data = new URLSearchParams({
                    action: "reg_black_delete_entry",
                    type,
                    value,
                    _wpnonce: nonce,
                });

                const response = await fetch(ajaxurl, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    body: data,
                });

                const result = await response.json();

                if (result.success) {
                    location.reload();
                } else {
                    alert("Failed to delete " + type + ". Please try again.");
                }
            } catch (error) {
                alert("An error occurred while deleting " + type + ".");
            }
        }
    }

    async function confirmDelete(type) {
        // Use a more modern confirmation approach, e.g., a modal
        return new Promise(resolve => {
            const userConfirmed = window.confirm("Are you sure you want to delete this " + type + "?");
            resolve(userConfirmed);
        });
    }

});