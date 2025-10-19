import { SAMPLE_LOGO } from './constants.js';
import wsApi from './signer/websocket.js';

export default () => ({
    ...wsApi,

    // Form data properties for two-way binding
    allowedStorages: ["JKS", "PKCS12"],
    isSigning: false,
    activeSubTab: 'xml',
    signatureType: 'xml',
    isArray: false,
    dataToSign: `\
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<root>
    <item>Сәлем, досым! Привет, друг!</item>
    <note>Бұл тест. Это тест.</note>
</root>`,
    decode: 'false',
    encapsulate: 'true',
    digested: 'false',
    tsaProfile: false,
    isAllowExpired: true,
    isAllowRevoked: true,
    isOutputCert: true,
    iin: '123456789012',
    bin: '012345678912',
    serialNumber: '',
    extKeyUsageOids: '',
    buildChain: false,
    caCerts: '',
    signature: '',

    initXmlSigner() {
        this.initWebSocket();
    },

    async handleCertificateSelection(detail) {
        const { userCert, legalCert, caCert } = detail;
        const cert = { ...userCert, ...legalCert };

        if (cert) {
            // Auto-populate signer parameters
            this.iin = cert.iin || this.iin;
            this.bin = cert.bin || this.bin;
            this.serialNumber = cert.serialNumber || this.serialNumber;
        }

        if(userCert) {
            this.bin = '';
        }

        // Try to get and set CA certificate if buildChain is enabled
        if (caCert) {
            const pemText = await this.$store.certificateStore.fetchCaCert();
            if(pemText) {
                this.caCerts = pemText;
                this.buildChain = true;
            }
        }

        if(userCert || caCert) {
            this.addNotification('success', 'Certificate parameters loaded automatically');
        }
    },

    async request() {
        this.isSigning = true;

        const selectedStorages = this.allowedStorages.filter(storage => storage); // Filter out empty values
        const signatureType = this.signatureType;
        let dataToSign = this.dataToSign;

        if (this.isArray) {
            dataToSign = [dataToSign];
        }

        const decode = this.decode === 'true';
        const encapsulate = this.encapsulate === 'true';
        const digested = this.digested === 'true';

        const extKeyUsageOidString = this.extKeyUsageOids;
        const extKeyUsageOids = extKeyUsageOidString ? extKeyUsageOidString.split(',').map(s => s.trim()) : [];

        const caCertsString = this.caCerts;
        let caCerts;
        if (this.buildChain) {
            caCerts = caCertsString ? caCertsString.split(',').map(s => s.trim()) : null;
        } else {
            caCerts = null;
        }

        const localeRadio = this.isKK ? 'kk' : 'ru';

        let tsaProfile = null;
        if (this.tsaProfile) {
            tsaProfile = {};
        }

        const iin = this.iin;
        const bin = this.bin;
        const serialNumber = this.serialNumber;

        const signInfo = {
            module: 'kz.gov.pki.knca.basics',
            method: 'sign',
            args: {
                allowedStorages: selectedStorages,
                format: signatureType,
                data: dataToSign,
                signingParams: { decode, encapsulate, digested, tsaProfile },
                signerParams: {
                    extKeyUsageOids,
                    iin,
                    bin,
                    serialNumber,
                    chain: caCerts
                },
                locale: localeRadio
            }
        };

        signInfo.args.logo = SAMPLE_LOGO;

        if (this.isAllowExpired) {
            signInfo.args.signingParams.allowExpired = true;
        }

        if (this.isAllowRevoked) {
            signInfo.args.signingParams.allowRevoked = true;
        }

        if (this.isOutputCert) {
            signInfo.args.signingParams.outputCert = true;
        }

        if (selectedStorages.length === 0) {
            delete signInfo.args.allowedStorages;
        }

        return this.connect().then((webSocket) => {
            this.logMessage('sent', signInfo);
            webSocket.send(JSON.stringify(signInfo));

            return new Promise((resolve) => {
                this.signingResolve = resolve;
            });
        }).catch((err) => {
            this.isSigning = false;
            console.error('Signing request failed:', err);
            this.addNotification('error', 'An error occurred during signing. Please check the console for details.');
        });
    },

    async sign() {
        // Validation
        if (!this.dataToSign.trim()) {
            this.addNotification('error', 'Data to sign cannot be empty');
            return;
        }
        const selectedStorages = this.allowedStorages.filter(storage => storage);
        if (selectedStorages.length === 0) {
            this.addNotification('error', 'At least one storage must be selected');
            return;
        }

        await this.request();
    },

    resetForm() {
        this.allowedStorages = ["JKS", "PKCS12"];
        this.isSigning = false;
        this.activeSubTab = 'xml';
        this.signatureType = 'xml';
        this.isArray = false;
        this.dataToSign = '';
        this.decode = 'false';
        this.encapsulate = 'true';
        this.digested = 'false';
        this.tsaProfile = false;
        this.isAllowExpired = true;
        this.isAllowRevoked = true;
        this.isOutputCert = true;
        this.iin = '123456789012';
        this.bin = '012345678912';
        this.serialNumber = '';
        this.extKeyUsageOids = '';
        this.buildChain = false;
        this.caCerts = '';
        this.signature = '';
    },

    copyToClipboard(text) {
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(() => {
                this.addNotification('success', 'Signature copied to clipboard!');
            }).catch(() => {
                this.fallbackCopyToClipboard(text);
            });
        } else {
            this.fallbackCopyToClipboard(text);
        }
    },

    fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            document.execCommand('copy');
            this.addNotification('success', 'Signature copied to clipboard!');
        } catch (err) {
            this.addNotification('error', 'Failed to copy signature to clipboard');
        }
        document.body.removeChild(textArea);
    },

    openDialog() {
        if (confirm(this.translate('connectionError'))) {
            location.reload();
        }
    },

    loadCaPem(event) {
        const file = event.target.files[0];
        if (file) {
            this.buildChain = true;
            file.text().then(text => {
                this.caCerts = text;
            });
        }
    },

    init() {

    },

});
