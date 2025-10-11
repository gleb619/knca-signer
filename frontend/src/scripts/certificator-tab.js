import * as api from './certificator/api.js';
import * as utils from './certificator/utils.js';

export default () => ({
    // Certificate collections - now hierarchical array structure
    /* Structure: Array of CA objects, each containing CA info and its user/legal certificates */
    certificates: [],

    // UI state
    generatingCA: false,
    generatingUser: false,
    generatingLegal: false,

    // Messages
    errorMessage: '',
    successMessage: '',

    // Form data
    newCAAlias: '',

    activeSubTab: 'create',

    async init() {
        await this.loadCertificates();
    },

    // Spread imported functionalities
    ...api,
    ...utils,

    // Enhanced action methods for Alpine.js component context
    async copyToClipboardHandler(text) {
        try {
            await this.copyToClipboard(text);
            this.successMessage = 'Copied to clipboard!';
            setTimeout(() => this.successMessage = '', 3000);
        } catch (err) {
            this.errorMessage = 'Failed to copy to clipboard';
            setTimeout(() => this.errorMessage = '', 5000);
        }
    },
});
