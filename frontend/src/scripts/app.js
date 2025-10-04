export default () => ({
    isKK: true,

    // Tab management
    activeTab: 'xml-signer', // xml-signer | certificate-authority
    isSigning: false,
    errorMessage: '',
    successMessage: '',

    init() {
        // Load locale from localStorage or default to 'kk'
        this.isKK = (localStorage.getItem('locale') || 'kk') == 'kk';
        console.log("[app] curr locale is: ", this.isKK);
        this.changeLocale(false);
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

    clearMessages() {
        this.errorMessage = '';
        this.successMessage = '';
    },

});
