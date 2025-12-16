// ==UserScript==
// @name         SVPN cookie getter
// @namespace    SVPN cookie getter
// @version      0.2
// @description  Gets the cookie to use with svpn-login
// @match        https://*.vpn.comcast.net/vdesk/webtop.eui*
// @grant        none
// ==/UserScript==

(function() {
    const resourceType = "network_access";
    with (new XMLHttpRequest()) with (location) {
        open("GET", `https://${host}:${port}/vdesk/resource_list.xml?resourcetype=res`);
        onload = () => document.documentElement.innerHTML = `<pre>${document.cookie.match(/MRHSession=(.*?); /)[1]}</pre>`;
        send();
    }
})();
