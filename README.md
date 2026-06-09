# Bulk PDF Signer

An offline browser tool that batch-signs PDF files with any PKCS#12
(`.p12` / `.pfx`) certificate. Each document gets a visible signature stamp
in the top-right corner of page 1 and a real, cryptographically verifiable
digital signature embedded in the file.

Works with **any RSA signing certificate** -- qualified eIDAS certificates,
commercial CA-issued certs, or self-signed test certificates. The name on
the stamp is read automatically from the certificate subject (common name,
plus e-mail when present).

## How to open it

Double-click `index.html`. It opens in your browser and runs directly from
disk over the `file://` protocol. There is nothing to install, build, or
start. It also works served from GitHub Pages -- the included workflow
(`.github/workflows/static.yml`) deploys the repository as a static site.

## Privacy

100% client-side. The tool makes **no network requests**: your certificate,
its password, and your documents never leave the browser. The password is
used once to unlock the certificate and is cleared from the form
immediately; nothing is written to local storage and there is no telemetry.

## How to use

1. **Choose certificate** -- pick your `.p12` / `.pfx` file, type its
   password, press **Unlock**. The signer name from the certificate is
   shown.
2. **Add PDFs** -- drop any number of PDF files onto the Documents pane, or
   click to choose. Files whose names already end in the output suffix are
   skipped automatically.
3. **Sign all** -- every file is signed in your browser. Each row shows its
   result: Signed, Skipped, or Failed (with the reason).
4. **Download** -- save files one by one, or use **Download all** to get a
   single `signed-pdfs.zip`.

**No certificate?** Type a name into **Stamp without certificate** instead.
The button changes to **Stamp all** and every PDF gets the same visible
stamp -- but no digital signature at all (see the limits below). An
unlocked certificate always takes priority over the typed name.

For each `report.pdf`, the tool produces `report_signed.pdf` (suffix
configurable under **Stamp options**).

## Signature appearance

The visible stamp is placed in the **top-right corner** of the first page.
It is rendered as a bitmap so text displays correctly in all PDF viewers:

```
[icon]  Digitally signed by:
        Jane Doe
        Date: 2026-06-09 19:50
```

The signer name always comes from **your certificate**, not from this tool --
titles like `Mgr.`, `Ing.`, or company names appear if they are part of the
certificate subject. Long names shrink to fit. Replace the default icon
under **Stamp options** (any PNG), or edit `assets/stamp-icon.svg`.

## Options

All options live in the **Stamp options** panel and apply to the next run
of **Sign all**.

| Option | Default | Description |
|--------|---------|-------------|
| Output suffix | `_signed` | Appended to the file name; also the skip rule |
| Signed-by label | `Digitally signed by:` | First line of the visible stamp |
| Date label | `Date:` | Prefix before the timestamp on the stamp |
| Signature reason | `Document electronically signed` | Stored in PDF signature metadata |
| Location | *(empty)* | Stored in PDF signature metadata |
| Timestamp format | `%Y-%m-%d %H:%M` | Supports `%Y %y %m %d %H %M %S` |
| Stamp icon | `assets/stamp-icon.png` | PNG shown on the left of the stamp |

### Czech labels (example)

Set the options to:

- Signed-by label: `Digitálně podepsal:`
- Date label: `Datum:`
- Signature reason: `Elektronický podpis dokumentu`
- Location: `CZ`
- Timestamp format: `%d.%m.%Y %H:%M`

## Certificate compatibility

| Certificate type | Supported |
|------------------|-----------|
| PKCS#12 (`.p12`, `.pfx`) with RSA key | Yes |
| Qualified / eIDAS (EU), RSA | Yes |
| Commercial CA signing certs, RSA | Yes |
| Self-signed (testing), RSA | Yes |
| ECDSA / EC keys | No |

The tool does not generate certificates -- you need your own `.p12` file
from your CA or trust service provider.

## Signature details and limits

- Signatures are detached CMS (PKCS#7), `adbe.pkcs7.detached`, SHA-256,
  with signing time, the full certificate chain from the `.p12`, and a
  visible signature field on page 1.
- **Stamp-only mode** (no certificate) draws the same visible stamp as
  page content but embeds **no digital signature** -- readers will not
  show the document as signed, and nothing about it is verifiable. Use it
  for visual marking only.
- PDF readers report the document as **signed and unmodified**. Whether the
  signature is shown as *trusted* depends on your certificate's chain being
  known to the reader -- exactly as with any other signing tool.
- Password-protected (encrypted) PDFs cannot be signed; remove the
  protection first.
- Signing rewrites the file, so a PDF that already carries a signature from
  another tool would lose that signature's validity. Sign original,
  unsigned documents (files ending in the suffix are skipped for this
  reason).

## Offline and dependencies

No build step, no server, no network requests, no telemetry. Two libraries
are vendored locally (never loaded from a CDN) because browsers provide no
native PKCS#12 or CMS support:

| Library | Version | File | Used for |
|---------|---------|------|----------|
| node-forge | 1.3.1 | `assets/js/vendor/forge.min.js` | PKCS#12 parsing, detached CMS signature |
| pdf-lib | 1.17.1 | `assets/js/vendor/pdf-lib.min.js` | PDF parsing, signature field, stamp embedding |

Everything else -- interface, stamp rendering, ZIP download -- is plain
HTML, CSS, and JavaScript using your system fonts.

## Files

```
index.html                      Markup and layout
assets/css/style.css            Visual system (desktop two-pane and mobile stacked)
assets/js/tool.js               Signing core (window.bulkPdfSigner) and UI wiring
assets/js/vendor/forge.min.js   Vendored node-forge 1.3.1
assets/js/vendor/pdf-lib.min.js Vendored pdf-lib 1.17.1
assets/stamp-icon.png           Default stamp icon (assets/stamp-icon.svg is the source)
.github/workflows/static.yml    GitHub Pages deployment
README.md                       This file
```

## License

MIT -- see [LICENSE](LICENSE).
