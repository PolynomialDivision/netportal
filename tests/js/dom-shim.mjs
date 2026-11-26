// The little DOM that static/render.js builds with (createElement, createElementNS,
// createTextNode, setAttribute, appendChild, textContent) and querySelectorAll for "tag[attr]",
// so its parts can be built and read under node. Not a browser: no parsing, no styles.

class Text {
  constructor(text) { this.nodeType = 3; this.data = String(text); }
  get textContent() { return this.data; }
}

class Element {
  constructor(tag, ns = null) {
    this.nodeType = 1;
    this.tagName = String(tag).toUpperCase();
    this.localName = String(tag).toLowerCase();
    this.namespaceURI = ns;
    this.attributes = new Map();
    this.childNodes = [];
  }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; }
  hasAttribute(name) { return this.attributes.has(name); }
  appendChild(node) { this.childNodes.push(node); return node; }
  get children() { return this.childNodes.filter((n) => n.nodeType === 1); }
  get textContent() { return this.childNodes.map((n) => n.textContent).join(""); }
  set textContent(value) { this.childNodes = [new Text(value)]; }
  get className() { return this.getAttribute("class") || ""; }
  /** Only "tag", "[attr]", "tag[attr]" and "[attr=value]" / '[attr="value"]'. */
  querySelectorAll(selector) {
    const m = /^([a-z0-9-]*)(?:\[([a-z-]+)(?:="?([^"\]]*)"?)?\])?$/.exec(selector.trim());
    if (!m) throw new Error(`dom-shim: unsupported selector ${selector}`);
    const [, tag, attr, value] = m;
    const out = [];
    const walk = (node) => {
      for (const child of node.childNodes) {
        if (child.nodeType !== 1) continue;
        if ((!tag || child.localName === tag) && (!attr || (child.hasAttribute(attr) && (value === undefined || child.getAttribute(attr) === value)))) {
          out.push(child);
        }
        walk(child);
      }
    };
    walk(this);
    return out;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  /** Markup, for reading in tests (attributes in the order they were set). */
  get outerHTML() {
    const attrs = [...this.attributes].map(([k, v]) => ` ${k}="${v.replace(/"/g, "&quot;")}"`).join("");
    const inner = this.childNodes.map((n) => (n.nodeType === 3 ? n.data.replace(/&/g, "&amp;").replace(/</g, "&lt;") : n.outerHTML)).join("");
    return `<${this.localName}${attrs}>${inner}</${this.localName}>`;
  }
}

export function installDom() {
  const document = {
    createElement: (tag) => new Element(tag),
    createElementNS: (ns, tag) => new Element(tag, ns),
    createTextNode: (text) => new Text(text),
  };
  globalThis.document = document;
  return document;
}
