/* Bulk PDF Signer.
   Classic script, window globals only. No imports, no exports, no network.
   Signing uses two vendored, locally served libraries (assets/js/vendor/):
   node-forge (PKCS#12 parsing + detached CMS/PKCS#7) and pdf-lib (PDF
   object model + incremental signature field). Everything runs in the
   browser; certificate, password and documents never leave the machine.
   The core never throws on user input: every entry point reports errors
   as Error objects with readable messages for the UI to display. */

/* ===================================================================
   1. Signing core  ->  window.bulkPdfSigner
   =================================================================== */
(function () {
  "use strict";

  /* Stamp geometry in PDF points, identical to the original CLI. */
  var STAMP = {
    w: 300,       /* visible stamp box width */
    h: 72,        /* visible stamp box height */
    margin: 24,   /* distance from the top-right page corner */
    icon: 44,     /* icon edge length */
    pad: 8,       /* inner padding left of the icon */
    gap: 10,      /* gap between icon and text column */
    scale: 2      /* canvas oversampling for crisp text */
  };

  /* Capacity reserved for the DER-encoded CMS container (hex in /Contents). */
  var PLACEHOLDER_BYTES = 8192;
  var BYTE_RANGE_TOKEN = "**********";

  /* Default stamp icon (assets/stamp-icon.png) embedded as a data URI so the
     canvas is never tainted when the page runs over the file:// protocol. */
  var DEFAULT_ICON_DATA_URI = "data:image/png;base64,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";

  /* ------------------------------------------------------- byte helpers */

  function bytesToBinary(bytes) {
    var out = "";
    var CHUNK = 0x8000;
    for (var i = 0; i < bytes.length; i += CHUNK) {
      out += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return out;
  }

  function dataUriToBytes(uri) {
    var base64 = String(uri).split(",")[1] || "";
    var bin = atob(base64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }
    return bytes;
  }

  function repeatChar(ch, count) {
    return new Array(count + 1).join(ch);
  }

  /* Find an ASCII needle inside a byte array. Bounds are optional. */
  function indexOfAscii(bytes, needle, from, to) {
    var start = Math.max(0, from || 0);
    var end = Math.min(bytes.length, to == null ? bytes.length : to) - needle.length;
    var first = needle.charCodeAt(0);
    for (var i = start; i <= end; i++) {
      if (bytes[i] !== first) { continue; }
      var hit = true;
      for (var j = 1; j < needle.length; j++) {
        if (bytes[i + j] !== needle.charCodeAt(j)) { hit = false; break; }
      }
      if (hit) { return i; }
    }
    return -1;
  }

  function lastIndexOfChar(bytes, ch, from) {
    var code = ch.charCodeAt(0);
    for (var i = from; i >= 0; i--) {
      if (bytes[i] === code) { return i; }
    }
    return -1;
  }

  function writeAscii(bytes, offset, text) {
    for (var i = 0; i < text.length; i++) {
      bytes[offset + i] = text.charCodeAt(i);
    }
  }

  function libs() {
    var forge = window.forge;
    var PDFLib = window.PDFLib;
    if (!forge || !PDFLib) {
      throw new Error("Vendored libraries failed to load. Keep assets/js/vendor/ next to index.html.");
    }
    return { forge: forge, PDFLib: PDFLib };
  }

  /* ------------------------------------------------------- file naming */

  function pdfStem(name) {
    return String(name).replace(/\.pdf$/i, "");
  }

  /* Mirrors the original CLI: a file whose stem already ends with the
     output suffix is considered signed and is skipped. */
  function isAlreadySigned(name, suffix) {
    if (!suffix) { return false; }
    var stem = pdfStem(name);
    return stem.length >= suffix.length &&
           stem.slice(stem.length - suffix.length) === suffix;
  }

  function outputName(name, suffix) {
    return pdfStem(name) + suffix + ".pdf";
  }

  /* --------------------------------------------------------- strftime */
  /* Tiny strftime subset matching the CLI default (%Y-%m-%d %H:%M). */
  function strftime(format, date) {
    function p2(n) { return (n < 10 ? "0" : "") + n; }
    return String(format).replace(/%([a-zA-Z%])/g, function (match, code) {
      switch (code) {
        case "Y": return String(date.getFullYear());
        case "y": return p2(date.getFullYear() % 100);
        case "m": return p2(date.getMonth() + 1);
        case "d": return p2(date.getDate());
        case "H": return p2(date.getHours());
        case "M": return p2(date.getMinutes());
        case "S": return p2(date.getSeconds());
        case "%": return "%";
        default: return match; /* unknown token: keep literally */
      }
    });
  }

  /* ------------------------------------------------- certificate loading */

  function subjectField(entity, selector) {
    var field = null;
    try { field = entity.getField(selector); } catch (e) { field = null; }
    if (!field || field.value == null) { return ""; }
    var value = String(field.value);
    /* BMPString values arrive as raw UTF-16BE bytes: decode for display. */
    if (field.valueTagClass === window.forge.asn1.Type.BMPSTRING) {
      var out = "";
      for (var i = 0; i + 1 < value.length; i += 2) {
        out += String.fromCharCode((value.charCodeAt(i) << 8) | value.charCodeAt(i + 1));
      }
      value = out;
    }
    return value;
  }

  /* forge keeps UTF8String attribute values as raw bytes. Decode them so
     names with diacritics display correctly AND so re-encoding the issuer
     DN inside the CMS SignerInfo reproduces the certificate's original
     bytes -- verifiers match the signer by issuer DN + serial number. */
  function normalizeDnEncoding(cert) {
    var forge = window.forge;
    var lists = [
      cert.subject && cert.subject.attributes,
      cert.issuer && cert.issuer.attributes
    ];
    for (var l = 0; l < lists.length; l++) {
      var attrs = lists[l] || [];
      for (var i = 0; i < attrs.length; i++) {
        if (attrs[i].valueTagClass === forge.asn1.Type.UTF8 &&
            typeof attrs[i].value === "string") {
          try { attrs[i].value = forge.util.decodeUtf8(attrs[i].value); }
          catch (e) { /* not valid UTF-8: keep the raw bytes */ }
        }
      }
    }
  }

  /* Parse a PKCS#12 file and return everything signing needs.
     Throws Error with a readable message on bad input. */
  function loadCertificate(p12Bytes, password) {
    var forge = libs().forge;

    var asn1;
    try {
      asn1 = forge.asn1.fromDer(bytesToBinary(p12Bytes));
    } catch (e) {
      throw new Error("This is not a valid PKCS#12 (.p12 / .pfx) file.");
    }

    var p12;
    try {
      p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password || "");
    } catch (e) {
      throw new Error("Could not unlock the certificate. Check the password.");
    }

    var oids = forge.pki.oids;
    var shrouded = p12.getBags({ bagType: oids.pkcs8ShroudedKeyBag })[oids.pkcs8ShroudedKeyBag] || [];
    var plain = p12.getBags({ bagType: oids.keyBag })[oids.keyBag] || [];
    var keyBag = shrouded[0] || plain[0];
    if (!keyBag) {
      throw new Error("No private key found inside the certificate file.");
    }
    var key = keyBag.key;
    if (!key || !key.n) {
      throw new Error("Unsupported private key type. Only RSA certificates are supported.");
    }

    var certBags = p12.getBags({ bagType: oids.certBag })[oids.certBag] || [];
    var certs = [];
    for (var i = 0; i < certBags.length; i++) {
      if (certBags[i].cert) {
        normalizeDnEncoding(certBags[i].cert);
        certs.push(certBags[i].cert);
      }
    }
    if (!certs.length) {
      throw new Error("No certificate found inside the file.");
    }

    var leaf = null;
    for (var c = 0; c < certs.length; c++) {
      var pub = certs[c].publicKey;
      if (pub && pub.n && pub.n.compareTo(key.n) === 0) { leaf = certs[c]; break; }
    }
    if (!leaf) { leaf = certs[0]; }
    var chain = [];
    for (var k = 0; k < certs.length; k++) {
      if (certs[k] !== leaf) { chain.push(certs[k]); }
    }

    /* Signer name from the certificate subject: CN, plus e-mail when present
       (same source as the original CLI -- never typed in by the user). */
    var cn = subjectField(leaf.subject, "CN") || "Unknown signer";
    var email = subjectField(leaf.subject, { name: "emailAddress" });
    var signerName = email ? cn + " <" + email + ">" : cn;

    return {
      key: key,
      cert: leaf,
      chain: chain,
      signerName: signerName,
      issuer: subjectField(leaf.issuer, "CN") || subjectField(leaf.issuer, "O"),
      notBefore: leaf.validity.notBefore,
      notAfter: leaf.validity.notAfter
    };
  }

  /* --------------------------------------------------- stamp rendering */

  function loadImage(src) {
    return new Promise(function (resolve, reject) {
      var img = new Image();
      img.onload = function () { resolve(img); };
      img.onerror = function () { reject(new Error("Could not load the stamp icon.")); };
      img.src = src;
    });
  }

  function fitFontSize(ctx, text, family, scale, maxWidth, maxSize, minSize) {
    for (var size = maxSize; size > minSize; size--) {
      ctx.font = (size * scale) + "px " + family;
      if (ctx.measureText(text).width <= maxWidth) { return size; }
    }
    return minSize;
  }

  /* Render the visible stamp bitmap with canvas (browser only):
     icon on the left, three text lines on the right, hairline border.
     Returns a Promise of PNG bytes. */
  function renderStamp(opts) {
    var iconUri = opts.iconDataUri || DEFAULT_ICON_DATA_URI;
    return loadImage(iconUri).then(function (icon) {
      var s = STAMP.scale;
      var family = '-apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, "Helvetica Neue", Arial, sans-serif';
      var canvas = document.createElement("canvas");
      canvas.width = STAMP.w * s;
      canvas.height = STAMP.h * s;
      var ctx = canvas.getContext("2d");

      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      var iconY = (STAMP.h - STAMP.icon) / 2;
      ctx.drawImage(icon, STAMP.pad * s, iconY * s, STAMP.icon * s, STAMP.icon * s);

      var textX = STAMP.pad + STAMP.icon + STAMP.gap;
      var maxWidth = (STAMP.w - textX - STAMP.pad) * s;
      var nameSize = fitFontSize(ctx, opts.signerName, family, s, maxWidth, 11, 7);

      var lines = [
        { text: opts.signedByLabel, size: 10 },
        { text: opts.signerName, size: nameSize },
        { text: opts.dateLabel + " " + opts.timestampText, size: 10 }
      ];

      ctx.fillStyle = "rgb(30, 30, 30)";
      ctx.textBaseline = "top";
      var y = 10;
      for (var i = 0; i < lines.length; i++) {
        ctx.font = (lines[i].size * s) + "px " + family;
        ctx.fillText(lines[i].text, textX * s, y * s, maxWidth);
        y += lines[i].size + 4;
      }

      /* 1pt frame, drawn into the bitmap like the original stamp border. */
      ctx.strokeStyle = "rgb(89, 89, 89)";
      ctx.lineWidth = s;
      ctx.strokeRect(s / 2, s / 2, canvas.width - s, canvas.height - s);

      return dataUriToBytes(canvas.toDataURL("image/png"));
    });
  }

  /* ----------------------------------------------------------- signing */

  function uniqueFieldName(doc) {
    var existing = {};
    try {
      var fields = doc.getForm().getFields();
      for (var i = 0; i < fields.length; i++) { existing[fields[i].getName()] = true; }
    } catch (e) { /* no form or malformed form: first name wins */ }
    var n = 1;
    while (existing["Signature" + n]) { n++; }
    return "Signature" + n;
  }

  /* Replace the ByteRange + Contents placeholders in the saved PDF with the
     real byte ranges and a detached CMS (PKCS#7) signature built by forge. */
  function injectSignature(bytes, certBundle, signingTime) {
    var forge = libs().forge;

    var tokenIdx = indexOfAscii(bytes, "/" + BYTE_RANGE_TOKEN);
    if (tokenIdx < 0) { throw new Error("Internal error: ByteRange placeholder not found."); }
    var brOpen = lastIndexOfChar(bytes, "[", tokenIdx);
    var brClose = indexOfAscii(bytes, "]", tokenIdx);
    if (brOpen < 0 || brClose < 0) { throw new Error("Internal error: ByteRange array not found."); }

    var zeros = repeatChar("0", PLACEHOLDER_BYTES * 2);
    /* The Contents placeholder serializes right after ByteRange; search a
       short window first and fall back to the whole file. */
    var contentsStart = indexOfAscii(bytes, "<" + zeros + ">", brClose, brClose + 2048);
    if (contentsStart < 0) { contentsStart = indexOfAscii(bytes, "<" + zeros + ">", brClose); }
    if (contentsStart < 0) { throw new Error("Internal error: Contents placeholder not found."); }
    var contentsEnd = contentsStart + zeros.length + 1; /* index of ">" */

    var range = [0, contentsStart, contentsEnd + 1, bytes.length - contentsEnd - 1];
    var brText = "[0 " + range[1] + " " + range[2] + " " + range[3] + "]";
    var available = brClose - brOpen + 1;
    if (brText.length > available) { throw new Error("Internal error: ByteRange does not fit its placeholder."); }
    writeAscii(bytes, brOpen, brText + repeatChar(" ", available - brText.length));

    /* Hash everything except the Contents hex string (including <>). */
    var signed = new Uint8Array(range[1] + range[3]);
    signed.set(bytes.subarray(0, range[1]), 0);
    signed.set(bytes.subarray(range[2]), range[1]);

    var p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(bytesToBinary(signed));
    p7.addCertificate(certBundle.cert);
    for (var i = 0; i < (certBundle.chain || []).length; i++) {
      p7.addCertificate(certBundle.chain[i]);
    }
    p7.addSigner({
      key: certBundle.key,
      certificate: certBundle.cert,
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: [
        { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
        { type: forge.pki.oids.messageDigest },
        { type: forge.pki.oids.signingTime, value: signingTime }
      ]
    });
    p7.sign({ detached: true });

    var derHex = forge.util.bytesToHex(forge.asn1.toDer(p7.toAsn1()).getBytes());
    if (derHex.length > zeros.length) {
      throw new Error("The certificate chain is too large for the signature placeholder.");
    }
    writeAscii(bytes, contentsStart + 1, derHex); /* the rest stays zero padding */
    return bytes;
  }

  /* Sign one PDF: add a visible signature field on page 1 (top-right),
     save, then inject the detached CMS signature.
     pdfBytes      Uint8Array of the source PDF
     stampPngBytes Uint8Array of the rendered stamp bitmap
     certBundle    result of loadCertificate()
     options       { reason, location, signingTime }
     Returns a Promise of the signed PDF as Uint8Array. */
  function signPdf(pdfBytes, stampPngBytes, certBundle, options) {
    var PDFLib = libs().PDFLib;
    var opts = options || {};
    var signingTime = opts.signingTime || new Date();

    return PDFLib.PDFDocument.load(pdfBytes, { updateMetadata: false })
      .catch(function (e) {
        var msg = e && e.message ? String(e.message) : "";
        if (/encrypt/i.test(msg)) {
          throw new Error("The PDF is password-protected (encrypted). Remove the protection first.");
        }
        throw new Error("Could not read the PDF file." + (msg ? " (" + msg + ")" : ""));
      })
      .then(function (doc) {
        return doc.embedPng(stampPngBytes).then(function (png) {
          var ctx = doc.context;
          var page = doc.getPage(0);
          var size = page.getSize();
          var x1 = size.width - STAMP.margin;
          var y1 = size.height - STAMP.margin;
          var x0 = x1 - STAMP.w;
          var y0 = y1 - STAMP.h;

          /* Appearance: a form XObject that paints the stamp bitmap. */
          var apStream = ctx.stream("q " + STAMP.w + " 0 0 " + STAMP.h + " 0 0 cm /Img Do Q", {
            Type: "XObject",
            Subtype: "Form",
            FormType: 1,
            BBox: [0, 0, STAMP.w, STAMP.h],
            Resources: { XObject: { Img: png.ref } }
          });
          var apRef = ctx.register(apStream);

          /* Signature dictionary. ByteRange must serialize before Contents:
             injectSignature scans forward from the ByteRange token. */
          var sigDict = ctx.obj({
            Type: "Sig",
            Filter: "Adobe.PPKLite",
            SubFilter: "adbe.pkcs7.detached",
            ByteRange: [
              0,
              PDFLib.PDFName.of(BYTE_RANGE_TOKEN),
              PDFLib.PDFName.of(BYTE_RANGE_TOKEN),
              PDFLib.PDFName.of(BYTE_RANGE_TOKEN)
            ],
            Contents: PDFLib.PDFHexString.of(repeatChar("0", PLACEHOLDER_BYTES * 2)),
            /* Text entries use UTF-16 PDF text strings so names and reasons
               with diacritics (e.g. Czech) survive intact. */
            Reason: PDFLib.PDFHexString.fromText(opts.reason || ""),
            M: PDFLib.PDFString.fromDate(signingTime),
            Name: PDFLib.PDFHexString.fromText(certBundle.signerName || "")
          });
          if (opts.location) {
            sigDict.set(PDFLib.PDFName.of("Location"), PDFLib.PDFHexString.fromText(opts.location));
          }
          var sigRef = ctx.register(sigDict);

          var fieldName = uniqueFieldName(doc);
          var widget = ctx.obj({
            Type: "Annot",
            Subtype: "Widget",
            FT: "Sig",
            Rect: [x0, y0, x1, y1],
            V: sigRef,
            T: PDFLib.PDFString.of(fieldName),
            F: 132, /* print + locked */
            P: page.ref,
            AP: { N: apRef }
          });
          var widgetRef = ctx.register(widget);

          var AnnotsKey = PDFLib.PDFName.of("Annots");
          var annots = page.node.lookupMaybe(AnnotsKey, PDFLib.PDFArray);
          if (annots) { annots.push(widgetRef); }
          else { page.node.set(AnnotsKey, ctx.obj([widgetRef])); }

          var AcroFormKey = PDFLib.PDFName.of("AcroForm");
          var acro = doc.catalog.lookupMaybe(AcroFormKey, PDFLib.PDFDict);
          if (!acro) {
            doc.catalog.set(AcroFormKey, ctx.obj({ SigFlags: 3, Fields: [widgetRef] }));
          } else {
            acro.set(PDFLib.PDFName.of("SigFlags"), PDFLib.PDFNumber.of(3));
            var FieldsKey = PDFLib.PDFName.of("Fields");
            var fields = acro.lookupMaybe(FieldsKey, PDFLib.PDFArray);
            if (fields) { fields.push(widgetRef); }
            else { acro.set(FieldsKey, ctx.obj([widgetRef])); }
          }

          /* No object streams: the placeholder must stay scannable bytes. */
          return doc.save({ useObjectStreams: false });
        });
      })
      .then(function (saved) {
        return injectSignature(saved, certBundle, signingTime);
      });
  }

  /* Stamp one PDF without a certificate: draws the visible stamp on page 1
     (top-right) as regular page content. The output carries NO digital
     signature -- PDF readers will not report it as signed. */
  function stampPdf(pdfBytes, stampPngBytes) {
    var PDFLib = libs().PDFLib;
    return PDFLib.PDFDocument.load(pdfBytes, { updateMetadata: false })
      .catch(function (e) {
        var msg = e && e.message ? String(e.message) : "";
        if (/encrypt/i.test(msg)) {
          throw new Error("The PDF is password-protected (encrypted). Remove the protection first.");
        }
        throw new Error("Could not read the PDF file." + (msg ? " (" + msg + ")" : ""));
      })
      .then(function (doc) {
        return doc.embedPng(stampPngBytes).then(function (png) {
          var page = doc.getPage(0);
          var size = page.getSize();
          page.drawImage(png, {
            x: size.width - STAMP.margin - STAMP.w,
            y: size.height - STAMP.margin - STAMP.h,
            width: STAMP.w,
            height: STAMP.h
          });
          return doc.save();
        });
      });
  }

  /* -------------------------------------------------------- ZIP writer */
  /* Minimal store-only (no compression) ZIP, enough for "Download all". */

  var CRC_TABLE = (function () {
    var table = new Uint32Array(256);
    for (var n = 0; n < 256; n++) {
      var c = n;
      for (var k = 0; k < 8; k++) {
        c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[n] = c >>> 0;
    }
    return table;
  })();

  function crc32(bytes) {
    var c = 0xffffffff;
    for (var i = 0; i < bytes.length; i++) {
      c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
    }
    return (c ^ 0xffffffff) >>> 0;
  }

  function dosDateTime(date) {
    var year = Math.max(1980, date.getFullYear());
    return {
      date: ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate(),
      time: (date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() >> 1)
    };
  }

  /* entries: [{ name: string, bytes: Uint8Array, date?: Date }] */
  function buildZip(entries) {
    var encoder = new TextEncoder();
    var parts = [];
    var central = [];
    var offset = 0;

    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i];
      var nameBytes = encoder.encode(entry.name);
      var crc = crc32(entry.bytes);
      var dt = dosDateTime(entry.date || new Date());

      var local = new Uint8Array(30 + nameBytes.length);
      var lv = new DataView(local.buffer);
      lv.setUint32(0, 0x04034b50, true);
      lv.setUint16(4, 20, true);            /* version needed */
      lv.setUint16(6, 0x0800, true);        /* UTF-8 file names */
      lv.setUint16(8, 0, true);             /* method: store */
      lv.setUint16(10, dt.time, true);
      lv.setUint16(12, dt.date, true);
      lv.setUint32(14, crc, true);
      lv.setUint32(18, entry.bytes.length, true);
      lv.setUint32(22, entry.bytes.length, true);
      lv.setUint16(26, nameBytes.length, true);
      lv.setUint16(28, 0, true);
      local.set(nameBytes, 30);

      parts.push(local, entry.bytes);
      central.push({ nameBytes: nameBytes, crc: crc, size: entry.bytes.length, offset: offset, dt: dt });
      offset += local.length + entry.bytes.length;
    }

    var centralStart = offset;
    for (var c = 0; c < central.length; c++) {
      var rec = central[c];
      var dir = new Uint8Array(46 + rec.nameBytes.length);
      var dv = new DataView(dir.buffer);
      dv.setUint32(0, 0x02014b50, true);
      dv.setUint16(4, 20, true);
      dv.setUint16(6, 20, true);
      dv.setUint16(8, 0x0800, true);
      dv.setUint16(10, 0, true);
      dv.setUint16(12, rec.dt.time, true);
      dv.setUint16(14, rec.dt.date, true);
      dv.setUint32(16, rec.crc, true);
      dv.setUint32(20, rec.size, true);
      dv.setUint32(24, rec.size, true);
      dv.setUint16(28, rec.nameBytes.length, true);
      dv.setUint32(42, rec.offset, true);
      dir.set(rec.nameBytes, 46);
      parts.push(dir);
      offset += dir.length;
    }

    var eocd = new Uint8Array(22);
    var ev = new DataView(eocd.buffer);
    ev.setUint32(0, 0x06054b50, true);
    ev.setUint16(8, central.length, true);
    ev.setUint16(10, central.length, true);
    ev.setUint32(12, offset - centralStart, true);
    ev.setUint32(16, centralStart, true);
    parts.push(eocd);

    var total = 0;
    for (var p = 0; p < parts.length; p++) { total += parts[p].length; }
    var zip = new Uint8Array(total);
    var at = 0;
    for (var q = 0; q < parts.length; q++) { zip.set(parts[q], at); at += parts[q].length; }
    return zip;
  }

  /* ------------------------------------------------------------- public */
  window.bulkPdfSigner = {
    STAMP: STAMP,
    loadCertificate: loadCertificate,
    renderStamp: renderStamp,
    signPdf: signPdf,
    stampPdf: stampPdf,
    strftime: strftime,
    buildZip: buildZip,
    isAlreadySigned: isAlreadySigned,
    outputName: outputName
  };
})();

/* ===================================================================
   2. User interface wiring
   =================================================================== */
(function () {
  "use strict";

  if (typeof document === "undefined") { return; } /* core-only environments */

  var core = window.bulkPdfSigner;
  var els = {};
  var statusTimer = null;

  var state = {
    certFile: null,    /* chosen .p12 File, not yet unlocked */
    cert: null,        /* result of loadCertificate() */
    iconDataUri: null, /* custom stamp icon as data URI, null = default */
    files: [],         /* { id, file, name, size, status, error, output, outName, els } */
    nextId: 1,
    signing: false
  };

  function byId(id) { return document.getElementById(id); }

  function ready(fn) {
    if (document.readyState !== "loading") { fn(); }
    else { document.addEventListener("DOMContentLoaded", fn); }
  }

  function setStatus(msg) { if (els.status) { els.status.textContent = msg; } }

  function flash(msg) {
    setStatus(msg);
    clearTimeout(statusTimer);
    statusTimer = setTimeout(function () { setStatus("Ready"); }, 2400);
  }

  function tick() {
    return new Promise(function (resolve) { setTimeout(resolve, 0); });
  }

  function formatSize(bytes) {
    if (bytes < 1024) { return bytes + " B"; }
    if (bytes < 1024 * 1024) { return (bytes / 1024).toFixed(0) + " KB"; }
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }

  function formatDay(date) {
    return date.getFullYear() + "-" +
      (date.getMonth() < 9 ? "0" : "") + (date.getMonth() + 1) + "-" +
      (date.getDate() < 10 ? "0" : "") + date.getDate();
  }

  /* ------------------------------------------------------------ download */
  function downloadBytes(bytes, name, type) {
    var blob = new Blob([bytes], { type: type || "application/octet-stream" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }

  /* --------------------------------------------------------------- state */
  function counts() {
    var total = state.files.length;
    if (!total) { return "Empty"; }
    var signedCount = 0, stampedCount = 0;
    for (var i = 0; i < total; i++) {
      if (state.files[i].status === "signed") { signedCount++; }
      if (state.files[i].status === "stamped") { stampedCount++; }
    }
    var parts = [total + (total === 1 ? " file" : " files")];
    if (signedCount) { parts.push(signedCount + " signed"); }
    if (stampedCount) { parts.push(stampedCount + " stamped"); }
    return parts.join(", ");
  }

  function hasStatus(status) {
    for (var i = 0; i < state.files.length; i++) {
      if (state.files[i].status === status) { return true; }
    }
    return false;
  }

  function isDone(item) {
    return item.status === "signed" || item.status === "stamped";
  }

  /* "sign" with an unlocked certificate; "stamp" (visible stamp only, no
     digital signature) when no certificate but a stamp name is typed. */
  function currentMode() {
    if (state.cert) { return "sign"; }
    if (els.stampNameInput.value.trim()) { return "stamp"; }
    return "";
  }

  function refreshState() {
    var mode = currentMode();
    var signable = hasStatus("ready") || hasStatus("failed");
    els.signBtn.disabled = state.signing || !mode || !signable;
    els.signBtn.textContent = mode === "stamp" ? "Stamp all" : "Sign all";
    els.downloadAllBtn.disabled = state.signing || !(hasStatus("signed") || hasStatus("stamped"));
    els.clearBtn.disabled = state.signing || state.files.length === 0;
    els.unlockBtn.disabled = state.signing || !state.certFile;
    els.filesCount.textContent = counts();
    els.setupCount.textContent = state.cert ? "Certificate ready"
      : (mode === "stamp" ? "Stamp-only mode" : "No certificate");
  }

  /* ----------------------------------------------------------- file rows */
  var BADGE = {
    ready: { text: "Ready", cls: "badge" },
    skipped: { text: "Skipped", cls: "badge badge-skipped" },
    signing: { text: "Working", cls: "badge badge-signing" },
    signed: { text: "Signed", cls: "badge badge-signed" },
    stamped: { text: "Stamped", cls: "badge badge-signed" },
    failed: { text: "Failed", cls: "badge badge-failed" }
  };

  function renderRow(item) {
    var badge = BADGE[item.status] || BADGE.ready;
    item.els.badge.className = badge.cls;
    item.els.badge.textContent = badge.text;
    item.els.meta.textContent = formatSize(item.size) +
      (isDone(item) && item.outName ? "  ->  " + item.outName : "");
    item.els.error.textContent = item.status === "failed" && item.error ? item.error : "";
    item.els.error.style.display = item.els.error.textContent ? "" : "none";
    item.els.downloadBtn.style.display = isDone(item) ? "" : "none";
    item.els.removeBtn.disabled = state.signing;
    item.els.downloadBtn.disabled = state.signing;
  }

  function addRow(item) {
    var li = document.createElement("li");
    li.className = "file-row";

    var main = document.createElement("div");
    main.className = "file-main";
    var title = document.createElement("p");
    title.className = "file-title";
    title.textContent = item.name;
    title.title = item.name;
    var meta = document.createElement("p");
    meta.className = "file-meta";
    main.appendChild(title);
    main.appendChild(meta);

    var badge = document.createElement("span");

    var actions = document.createElement("div");
    actions.className = "file-actions";
    var downloadBtn = document.createElement("button");
    downloadBtn.type = "button";
    downloadBtn.className = "btn btn-row";
    downloadBtn.textContent = "Download";
    downloadBtn.addEventListener("click", function () {
      if (item.output) { downloadBytes(item.output, item.outName, "application/pdf"); }
    });
    var removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "btn btn-ghost btn-row";
    removeBtn.textContent = "Remove";
    removeBtn.setAttribute("aria-label", "Remove " + item.name);
    removeBtn.addEventListener("click", function () { removeFile(item.id); });
    actions.appendChild(downloadBtn);
    actions.appendChild(removeBtn);

    var error = document.createElement("p");
    error.className = "file-error";
    error.style.display = "none";

    li.appendChild(main);
    li.appendChild(badge);
    li.appendChild(actions);
    li.appendChild(error);
    els.fileList.appendChild(li);

    item.els = { row: li, badge: badge, meta: meta, error: error, downloadBtn: downloadBtn, removeBtn: removeBtn };
    renderRow(item);
  }

  function removeFile(id) {
    if (state.signing) { return; }
    for (var i = 0; i < state.files.length; i++) {
      if (state.files[i].id === id) {
        els.fileList.removeChild(state.files[i].els.row);
        state.files.splice(i, 1);
        break;
      }
    }
    refreshState();
  }

  function currentSuffix() { return els.suffixInput.value; }

  function addFiles(fileList) {
    var added = 0, dupes = 0, notPdf = 0;
    for (var i = 0; i < fileList.length; i++) {
      var file = fileList[i];
      if (!/\.pdf$/i.test(file.name)) { notPdf++; continue; }
      var duplicate = false;
      for (var j = 0; j < state.files.length; j++) {
        if (state.files[j].name === file.name && state.files[j].size === file.size) { duplicate = true; break; }
      }
      if (duplicate) { dupes++; continue; }

      var item = {
        id: state.nextId++,
        file: file,
        name: file.name,
        size: file.size,
        status: core.isAlreadySigned(file.name, currentSuffix()) ? "skipped" : "ready",
        error: "",
        output: null,
        outName: "",
        els: null
      };
      state.files.push(item);
      addRow(item);
      added++;
    }
    refreshState();
    var note = [];
    if (added) { note.push("Added " + added + " PDF" + (added === 1 ? "" : "s")); }
    if (dupes) { note.push(dupes + " already in the list"); }
    if (notPdf) { note.push(notPdf + " not a PDF"); }
    flash(note.length ? note.join(", ") : "No PDF files found");
  }

  /* Re-apply the skip rule when the suffix changes (signed rows stay). */
  function recomputeSkips() {
    for (var i = 0; i < state.files.length; i++) {
      var item = state.files[i];
      if (item.status === "ready" || item.status === "skipped") {
        item.status = core.isAlreadySigned(item.name, currentSuffix()) ? "skipped" : "ready";
        renderRow(item);
      }
    }
    refreshState();
  }

  /* --------------------------------------------------------- certificate */
  function unlockCertificate() {
    if (!state.certFile) { return; }
    var file = state.certFile;
    setStatus("Unlocking certificate...");
    file.arrayBuffer().then(function (buffer) {
      var bundle = core.loadCertificate(new Uint8Array(buffer), els.passInput.value);
      state.cert = bundle;
      els.passInput.value = ""; /* the password is never kept after unlock */
      els.certInfo.className = "cert-info is-ok";
      els.certInfo.textContent = "Signer: " + bundle.signerName +
        (bundle.issuer ? " | Issuer: " + bundle.issuer : "") +
        " | Valid until: " + formatDay(bundle.notAfter) +
        (bundle.notAfter < new Date() ? " (expired)" : "");
      refreshState();
      flash("Certificate unlocked");
    }).catch(function (e) {
      state.cert = null;
      els.certInfo.className = "cert-info is-error";
      els.certInfo.textContent = e && e.message ? e.message : "Could not read the certificate file.";
      refreshState();
      flash("Certificate not unlocked");
    });
  }

  /* --------------------------------------------------------------- signing */
  function signAll() {
    var mode = currentMode();
    if (state.signing || !mode) { return; }
    var suffix = currentSuffix();
    if (!suffix) {
      flash("The output suffix must not be empty.");
      return;
    }
    recomputeSkips();

    var queue = [];
    for (var i = 0; i < state.files.length; i++) {
      var st = state.files[i].status;
      if (st === "ready" || st === "failed") { queue.push(state.files[i]); }
    }
    if (!queue.length) { flash("No PDF files to sign."); return; }

    state.signing = true;
    refreshState();
    setStatus("Preparing stamp...");

    var now = new Date();
    var verb = mode === "sign" ? "Signing " : "Stamping ";
    var options = {
      reason: els.reasonInput.value,
      location: els.locationInput.value,
      signingTime: now
    };

    core.renderStamp({
      signerName: mode === "sign" ? state.cert.signerName : els.stampNameInput.value.trim(),
      signedByLabel: els.signedByInput.value,
      dateLabel: els.dateLabelInput.value,
      timestampText: core.strftime(els.formatInput.value, now),
      iconDataUri: state.iconDataUri
    }).then(function (stampPng) {
      var done = 0, failed = 0;

      function next(index) {
        if (index >= queue.length) {
          state.signing = false;
          refreshState();
          var summary = (mode === "sign" ? "Signed " : "Stamped ") + done + " of " + queue.length +
                        (failed ? ", " + failed + " failed" : "");
          if (mode === "stamp" && done) { summary += " (no digital signature)"; }
          flash(summary);
          return;
        }
        var item = queue[index];
        item.status = "signing";
        item.error = "";
        renderRow(item);
        setStatus(verb + item.name + " (" + (index + 1) + "/" + queue.length + ")...");

        item.file.arrayBuffer().then(function (buffer) {
          var bytes = new Uint8Array(buffer);
          return mode === "sign"
            ? core.signPdf(bytes, stampPng, state.cert, options)
            : core.stampPdf(bytes, stampPng);
        }).then(function (outBytes) {
          item.output = outBytes;
          item.outName = core.outputName(item.name, suffix);
          item.status = mode === "sign" ? "signed" : "stamped";
          done++;
        }).catch(function (e) {
          item.status = "failed";
          item.error = e && e.message ? e.message : (verb.trim() + " failed.");
          failed++;
        }).then(function () {
          renderRow(item);
          refreshState();
          return tick();
        }).then(function () {
          next(index + 1);
        });
      }

      next(0);
    }).catch(function (e) {
      state.signing = false;
      refreshState();
      flash(e && e.message ? e.message : "Could not prepare the stamp.");
    });
  }

  function downloadAll() {
    var entries = [];
    for (var i = 0; i < state.files.length; i++) {
      var item = state.files[i];
      if (isDone(item) && item.output) {
        entries.push({ name: item.outName, bytes: item.output, date: new Date() });
      }
    }
    if (!entries.length) { return; }
    if (entries.length === 1) {
      downloadBytes(entries[0].bytes, entries[0].name, "application/pdf");
      flash("Downloaded " + entries[0].name);
      return;
    }
    try {
      var zip = core.buildZip(entries);
      downloadBytes(zip, "signed-pdfs.zip", "application/zip");
      flash("Downloaded signed-pdfs.zip (" + entries.length + " files)");
    } catch (e) {
      flash("Could not build the ZIP archive.");
    }
  }

  function clearList() {
    if (state.signing) { return; }
    state.files = [];
    els.fileList.textContent = "";
    refreshState();
    setStatus("Ready");
  }

  /* ----------------------------------------------------------------- setup */
  ready(function () {
    els.signBtn = byId("signBtn");
    els.addBtn = byId("addBtn");
    els.downloadAllBtn = byId("downloadAllBtn");
    els.clearBtn = byId("clearBtn");
    els.pdfInput = byId("pdfInput");
    els.certInput = byId("certInput");
    els.iconInput = byId("iconInput");
    els.certBtn = byId("certBtn");
    els.certFileName = byId("certFileName");
    els.passInput = byId("passInput");
    els.unlockBtn = byId("unlockBtn");
    els.certInfo = byId("certInfo");
    els.stampNameInput = byId("stampNameInput");
    els.suffixInput = byId("suffixInput");
    els.signedByInput = byId("signedByInput");
    els.dateLabelInput = byId("dateLabelInput");
    els.reasonInput = byId("reasonInput");
    els.locationInput = byId("locationInput");
    els.formatInput = byId("formatInput");
    els.iconBtn = byId("iconBtn");
    els.iconResetBtn = byId("iconResetBtn");
    els.iconFileName = byId("iconFileName");
    els.dropZone = byId("dropZone");
    els.fileList = byId("fileList");
    els.filesCount = byId("filesCount");
    els.setupCount = byId("setupCount");
    els.status = byId("status");

    /* Certificate */
    els.certBtn.addEventListener("click", function () { els.certInput.click(); });
    els.certInput.addEventListener("change", function (e) {
      var file = e.target.files && e.target.files[0];
      if (!file) { return; }
      state.certFile = file;
      state.cert = null;
      els.certFileName.textContent = file.name;
      els.certInfo.className = "cert-info";
      els.certInfo.textContent = "Enter the password and press Unlock.";
      els.certInput.value = "";
      refreshState();
      els.passInput.focus();
    });
    els.unlockBtn.addEventListener("click", unlockCertificate);
    els.passInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !els.unlockBtn.disabled) { unlockCertificate(); }
    });

    /* Stamp-only mode: typing a name enables the button without a cert. */
    els.stampNameInput.addEventListener("input", refreshState);

    /* Options */
    els.suffixInput.addEventListener("input", recomputeSkips);
    els.iconBtn.addEventListener("click", function () { els.iconInput.click(); });
    els.iconInput.addEventListener("change", function (e) {
      var file = e.target.files && e.target.files[0];
      els.iconInput.value = "";
      if (!file) { return; }
      var reader = new FileReader();
      reader.onload = function () {
        state.iconDataUri = String(reader.result || "");
        els.iconFileName.textContent = file.name;
        els.iconResetBtn.disabled = false;
        flash("Stamp icon set to " + file.name);
      };
      reader.onerror = function () { flash("Could not read that icon."); };
      reader.readAsDataURL(file);
    });
    els.iconResetBtn.addEventListener("click", function () {
      state.iconDataUri = null;
      els.iconFileName.textContent = "Default icon";
      els.iconResetBtn.disabled = true;
      flash("Stamp icon reset to default");
    });

    /* Documents */
    els.addBtn.addEventListener("click", function () { els.pdfInput.click(); });
    els.dropZone.addEventListener("click", function () { els.pdfInput.click(); });
    els.pdfInput.addEventListener("change", function (e) {
      if (e.target.files && e.target.files.length) { addFiles(e.target.files); }
      els.pdfInput.value = ""; /* allow re-adding the same files */
    });

    ["dragenter", "dragover"].forEach(function (type) {
      els.dropZone.addEventListener(type, function (e) {
        e.preventDefault();
        els.dropZone.classList.add("is-drag");
      });
    });
    ["dragleave", "drop"].forEach(function (type) {
      els.dropZone.addEventListener(type, function (e) {
        e.preventDefault();
        els.dropZone.classList.remove("is-drag");
      });
    });
    els.dropZone.addEventListener("drop", function (e) {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
        addFiles(e.dataTransfer.files);
      }
    });
    /* Dropping outside the zone must not navigate away from the tool. */
    document.addEventListener("dragover", function (e) { e.preventDefault(); });
    document.addEventListener("drop", function (e) { e.preventDefault(); });

    /* Toolbar */
    els.signBtn.addEventListener("click", signAll);
    els.downloadAllBtn.addEventListener("click", downloadAll);
    els.clearBtn.addEventListener("click", clearList);

    refreshState();
    setStatus("Ready");
  });
})();
