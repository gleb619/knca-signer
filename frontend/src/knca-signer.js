import './css/style.scss';

import Alpine from 'alpinejs';
import htmx from 'htmx.org';

import { Translator } from '@owja/i18n';
import kk from "./i18n/kk.json";
import ru from "./i18n/ru.json";

window.htmx = htmx;
window.Alpine = Alpine;
window.knca = {
    translator: new Translator({ default:"kk", fallback:"ru" })
};

window.knca.translator.addResource("kk", kk);
window.knca.translator.addResource("ru", ru);

import ncaApp from './scripts/app.js';
import xmlSignerTab from './scripts/xml-signer-tab.js';
import certificatorTab from './scripts/certificator-tab.js';

// Register Alpine components immediately
Alpine.data('ncaApp', ncaApp);
Alpine.data('xmlSignerTab', xmlSignerTab);
Alpine.data('certificatorTab', certificatorTab);

// Configure HTMX for Alpine.js integration
document.addEventListener('DOMContentLoaded', () => {
    
    // Initialize HTMX extensions
    if (window.htmx) {
        // Configure Alpine Morph extension
        htmx.config.globalViewTransitions = true;
        
        // Add HTMX event listener to reinitialize Alpine components after swaps
        document.addEventListener('htmx:afterSwap', (evt) => {
            // Re-initialize Alpine on HTMX content swaps
            if (window.Alpine && evt.detail.target) {
                window.Alpine.initTree(evt.detail.target);
                htmx.process(evt.detail.target);
            }
        });
    }
});

Alpine.start();

const element = document.querySelector('[x-data="ncaApp"]');
if(element) {
    element.style.removeProperty('display');
}
