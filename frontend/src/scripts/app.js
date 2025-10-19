export default () => ({
    isKK: true,

    // Tab management
    activeTab: 'loader', // certificate-authority | xml-signer | xml-verifier | loader

    notifications: [],

    init() {
        // Load locale from localStorage or default to 'kk'
        this.isKK = (localStorage.getItem('locale') || 'kk') == 'kk';
        console.log("[app] curr locale is: ", this.isKK);
        this.changeLocale(false);
    },

    onAppStarted() {
        const urlParams = new URLSearchParams(window.location.search);
        const tabFromUrl = urlParams.get('tab');
        if (['certificate-authority', 'xml-signer', 'xml-verifier'].includes(tabFromUrl)) {
            this.selectTab(tabFromUrl);
        } else {
            setTimeout(() => {
                this.selectTab('certificate-authority');
            }, 20);
        }
    },

    changeLocale(shouldReload = true) {
        const newLocale = this.isKK ? 'kk' : 'ru';
        console.log("[app] new locale is: ", newLocale);

        localStorage.setItem('locale', newLocale);
        window.knca.translator.locale(newLocale);
        if(shouldReload) {
            location.reload(true);
        }
    },

    translate(key) {
        return window.knca.translator.t(key);
    },

    addNotification(type, message) {
        const notification = {
            type, // 'error' or 'success'
            message,
            timestamp: Date.now()
        };
        this.notifications.push(notification);

        const timeout = type === 'error' ? 5000 : 3000;
        setTimeout(() => {
            this.removeNotification(notification);
        }, timeout);
    },

    removeNotification(notification) {
        const index = this.notifications.indexOf(notification);
        if (index > -1) {
            this.notifications.splice(index, 1);
        }
    },

    clearAllNotifications() {
        this.notifications = [];
    },

    selectTab(tab) {
        this.activeTab = tab;
        document.title = this.translate(tab);
        const url = new URL(window.location);
        url.searchParams.set('tab', tab);
        window.history.pushState({}, '', url);
    },

});
