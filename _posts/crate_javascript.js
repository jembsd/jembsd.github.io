'use strict';
/** @type {!Array} */
var _0x2752 = ["cXVlcnlTZWxlY3RvckFsbA==", "LmxvY2sgaW5wdXQ=", "a2V5dXA=", "dXBkYXRl", "Y2hhbmdl", "aW5wdXQ=", "dW5sb2Nr", "YXBwbGljYXRpb24vanNvbg==", "c3RyaW5naWZ5", "c3RhdHVz", "RmFpbGVkIHRvIGZldGNoIGRhdGEu", "RmFpbGVkIHRvIGRhdGEu", "anNvbg==", "IGlucHV0", "IGJ1dHRvbg==", "YWRk", "dW5sb2NrZWQ=", "ZGlzYWJsZWQ=", "Y29kZQ==", "b3Blbg==", "UE9TVA==", "dGhlbg==", "ZXJyb3I=", "cmV3YXJk", "V2VsbCBkb25lISBIZXJlJ3MgdGhlIHBhc3N3b3JkOg==", "YmFja2dyb3VuZDogeWVsbG93OyBjb2xvcjogYmxhY2s7IGZvbnQtd2VpZ2h0OiBib2xkOyBmb250LXNpemU6IDEuNWVtOyBwYWRkaW5nOiAzY2ggNGNoOw==",
"ZHVyYXRpb24=", "c2Vjb25kcw==", "RmVlbCBmcmVlIHRvIHVzZSB0aGlzIGhhbmR5IGltYWdlIHRvIHNoYXJlIHlvdXIgc2NvcmUh", "cmVtb3ZlQ2hpbGQ=", "LmJveA==", "Y3JlYXRlRWxlbWVudA==", "ZGl2", "Y2xhc3NMaXN0", "c2NvcmU=", "cHJlcGVuZA==", "c3R5bGU=", "YmFja2dyb3VuZEltYWdl", "dXJsKA==", "aW1hZ2U=", "RkFJTA==", "LmxvY2sgYnV0dG9u", "ZGF0YS1jb2Rl", "LmxvY2tzID4gbGkgPiAubG9jay5jMTAgPiAuY29tcG9uZW50LnN3YWI=", "TWlzc2luZyBjb3R0b24gc3dhYiE=", "LmxvY2tzID4gbGkgPiAubG9jay5jMTAgPiAuY29tcG9uZW50Lmdub21l", "TWlzc2luZyBnbm9tZSE=", "LmhpbnQtZGlzcGVuc2Vy",
"Y2xpY2s=", "cGFyZW50RWxlbWVudA==", "LmhpbnQ=", "aW5uZXJUZXh0", "TmVlZCBhbm90aGVyIGhpbnQ/", "aGludA==", "aW5zZXJ0QmVmb3Jl", "ZG9jdW1lbnRFbGVtZW50", "ZG9TY3JvbGw=", "dGVzdA==", "cmVhZHlTdGF0ZQ==", "cmVtb3ZlRXZlbnRMaXN0ZW5lcg==", "RE9NQ29udGVudExvYWRlZA==", "c2hpZnQ=", "UmVxdWVzdA==", "UmVzcG9uc2U=", "RE9NRXhjZXB0aW9u", "ZmV0Y2g=", "VVJMU2VhcmNoUGFyYW1z", "U3ltYm9s", "aXRlcmF0b3I=", "QmxvYg==", "Rm9ybURhdGE=", "QXJyYXlCdWZmZXI=", "W29iamVjdCBJbnQ4QXJyYXld", "W29iamVjdCBVaW50OEFycmF5XQ==", "W29iamVjdCBVaW50OENsYW1wZWRBcnJheV0=",
"W29iamVjdCBVaW50MTZBcnJheV0=", "W29iamVjdCBJbnQzMkFycmF5XQ==", "W29iamVjdCBVaW50MzJBcnJheV0=", "W29iamVjdCBGbG9hdDMyQXJyYXld", "aXNWaWV3", "aW5kZXhPZg==", "dG9TdHJpbmc=", "c3RyaW5n", "SW52YWxpZCBjaGFyYWN0ZXIgaW4gaGVhZGVyIGZpZWxkIG5hbWU=", "dG9Mb3dlckNhc2U=", "aXRlcmFibGU=", "YXBwZW5k", "aXNBcnJheQ==", "Z2V0T3duUHJvcGVydHlOYW1lcw==", "Ym9keVVzZWQ=", "cmVqZWN0", "QWxyZWFkeSByZWFk", "b25sb2Fk", "cmVzdWx0", "cmVhZEFzQXJyYXlCdWZmZXI=", "c2xpY2U=", "c2V0", "YnVmZmVy", "X2luaXRCb2R5", "X2JvZHlJbml0", "X2JvZHlUZXh0",
"YmxvYg==", "aXNQcm90b3R5cGVPZg==", "X2JvZHlCbG9i", "Zm9ybURhdGE=", "c2VhcmNoUGFyYW1z", "YXJyYXlCdWZmZXI=", "X2JvZHlBcnJheUJ1ZmZlcg==", "Y29udGVudC10eXBl", "dGV4dC9wbGFpbjtjaGFyc2V0PVVURi04", "dHlwZQ==", "aGVhZGVycw==", "YXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkO2NoYXJzZXQ9VVRGLTg=", "cmVzb2x2ZQ==", "X2JvZHlGb3JtRGF0YQ==", "Y291bGQgbm90IHJlYWQgRm9ybURhdGEgYm9keSBhcyBibG9i", "cmVhZEFzVGV4dA==", "ZnJvbUNoYXJDb2Rl", "am9pbg==", "dGV4dA==", "cGFyc2U=", "bWFw", "ZGVsZXRl", "Z2V0", "aGFz", "aGFzT3duUHJvcGVydHk=",
"dmFsdWVz", "ZW50cmllcw==", "SEVBRA==", "T1BUSU9OUw==", "UFVU", "Ym9keQ==", "dXJs", "Y3JlZGVudGlhbHM=", "bWV0aG9k", "bW9kZQ==", "c2lnbmFs", "c2FtZS1vcmlnaW4=", "dG9VcHBlckNhc2U=", "Qm9keSBub3QgYWxsb3dlZCBmb3IgR0VUIG9yIEhFQUQgcmVxdWVzdHM=", "dHJpbQ==", "c3BsaXQ=", "c3RhdHVzVGV4dA==", "cmVkaXJlY3Q=", "SW52YWxpZCBzdGF0dXMgY29kZQ==", "bmFtZQ==", "c3RhY2s=", "YWJvcnRlZA==", "QWJvcnRlZA==", "QWJvcnRFcnJvcg==", "YWJvcnQ=", "Z2V0QWxsUmVzcG9uc2VIZWFkZXJz", "cmVwbGFjZQ==", "cmVzcG9uc2VVUkw=", "WC1SZXF1ZXN0LVVSTA==",
"cmVzcG9uc2U=", "cmVzcG9uc2VUZXh0", "b25lcnJvcg==", "TmV0d29yayByZXF1ZXN0IGZhaWxlZA==", "aW5jbHVkZQ==", "d2l0aENyZWRlbnRpYWxz", "b21pdA==", "cmVzcG9uc2VUeXBl", "c2V0UmVxdWVzdEhlYWRlcg==", "b25yZWFkeXN0YXRlY2hhbmdl", "cG9seWZpbGw=", "SGVhZGVycw==", "ODE0NjZjMTkxMGQ5", "YmluZA==", "ZXhwb3J0cw==", "Y2FsbA==", "dW5kZWZpbmVk", "dG9TdHJpbmdUYWc=", "ZGVmaW5lUHJvcGVydHk=", "TW9kdWxl", "X19lc01vZHVsZQ==", "b2JqZWN0", "Y3JlYXRl", "ZGVmYXVsdA==", "cHJvdG90eXBl", "MzE3Nzg0NTQyNDkz", "YTEwYjRkY2U4YmI0", "M2NhNDg2Y2RmNTcx",
"a2V5cw==", "Z2V0T3duUHJvcGVydHlTeW1ib2xz", "ZmlsdGVy", "Z2V0T3duUHJvcGVydHlEZXNjcmlwdG9y", "cHVzaA==", "YXBwbHk=", "bGVuZ3Ro", "Zm9yRWFjaA==", "Z2V0T3duUHJvcGVydHlEZXNjcmlwdG9ycw==", "ZGVmaW5lUHJvcGVydGllcw==", "MzI0OTBlYmYtNTM3Zi00NTk2LTg3NWItZDMwZmJiYjQ3ZGE2", "bG9n", "c2VlZDo=", "R29vZ2xlOiAiW3lvdXIgYnJvd3NlciBuYW1lXSBkZXZlbG9wZXIgdG9vbHMgY29uc29sZSI=", "VGhlIGNvZGUgaXMgOCBjaGFyIGFscGhhbnVtZXJpYw==", "TW9zdCBwYXBlciBpcyBtYWRlIG91dCBvZiBwdWxwLg==", "SG93IGNhbiB5b3UgdmlldyB0aGlzIHBhZ2Ugb24gcGFwZXI/",
"R29vZ2xlOiAiW3lvdXIgYnJvd3NlciBuYW1lXSB2aWV3IG5ldHdvcmsi", "R29vZ2xlOiAiW3lvdXIgYnJvd3NlciBuYW1lXSB2aWV3IGxvY2FsIHN0b3JhZ2Ui", "VGhlcmUgYXJlIHNldmVyYWwgd2F5cyB0byBzZWUgdGhlIGZ1bGwgcGFnZSB0aXRsZToKLSBIb3ZlcmluZyBvdmVyIHRoaXMgYnJvd3NlciB0YWIgd2l0aCB5b3VyIG1vdXNlCi0gRmluZGluZyBhbmQgb3BlbmluZyB0aGUgPHRpdGxlPiBlbGVtZW50IGluIHRoZSBET00gdHJlZQotIFR5cGluZyBgZG9jdW1lbnQudGl0bGVgIGludG8gdGhlIGNvbnNvbGU=", "SW4gdGhlIGBmb250LWZhbWlseWAgY3NzIHByb3BlcnR5LCB5b3UgY2FuIGxpc3QgbXVsdGlwbGUgZm9udHMsIGFuZCB0aGUgZmlyc3QgYXZhaWxhYmxlIGZvbnQgb24gdGhlIHN5c3RlbSB3aWxsIGJlIHVzZWQu",
"R29vZ2xlOiAiW3lvdXIgYnJvd3NlciBuYW1lXSB2aWV3IGV2ZW50IGhhbmRsZXJzIg==", "YDphY3RpdmVgIGlzIGEgY3NzIHBzZXVkbyBjbGFzcyB0aGF0IGlzIGFwcGxpZWQgb24gZWxlbWVudHMgaW4gYW4gYWN0aXZlIHN0YXRlLg==", "R29vZ2xlOiAiW3lvdXIgYnJvd3NlciBuYW1lXSBmb3JjZSBwc3VkbyBjbGFzc2VzIg==", "SWYgYW4gYWN0aW9uIGRvZXNuJ3QgcHJvZHVjZSB0aGUgZGVzaXJlZCBlZmZlY3QsIGNoZWNrIHRoZSBjb25zb2xlIGZvciBlcnJvciBvdXRwdXQu", "QmUgc3VyZSB0byBleGFtaW5lIHRoYXQgcHJpbnRlZCBjaXJjdWl0IGJvYXJkLg==", "aW1hZ2VzLzMyNDkwZWJmLTUzN2YtNDU5Ni04NzViLWQzMGZiYmI0N2RhNi5wbmc=",
"R0VU", "YXR0cmlidXRlcw==", "ZGF0YS1pZA==", "dmFsdWU=", "Y3VycmVudFRhcmdldA==", "cXVlcnlTZWxlY3Rvcg==", "LmxvY2suYw==", "LmVnZ3M=", "YWRkRXZlbnRMaXN0ZW5lcg==", "c3BvaWw=", "Y2xlYXI=", "JWPilosKJWNaWjRNRldUTiAlYwrilosK4paLCuKWiwrilosK4paLCuKWiwrilosK4paLCuKWiwrilosK4paLCuKWiwrilosK4paLCuKWiwrilosK4paLCuKWiwrilosK4paLCuKWiwrilosK4paLCuKWiwrilosK4paLCuKWiwrilosK4paLCuKWiwrilosK4paLCuKWiwrilosK4paL", "YmFja2dyb3VuZDogZ3JlZW47IGNvbG9yOiB3aGl0ZTsgZm9udC13ZWlnaHQ6IGJvbGQ7IGZvbnQtc2l6ZTogMS4yNWVtOyBwYWRkaW5nOiAzY2ggNGNoOw==",
"8J+bou+4j/Cfm6LvuI/wn5ui77iP"];
(function(data, i) {
  /**
   * @param {number} isLE
   * @return {undefined}
   */
  var write = function(isLE) {
    for (; --isLE;) {
      data["push"](data["shift"]());
    }
  };
  write(++i);
})(_0x2752, 169);
/**
 * @param {string} p
 * @param {?} altCss
 * @return {?}
 */
var _0x13fa = function(p, altCss) {
  /** @type {number} */
  p = p - 0;
  var newValue = _0x2752[p];
  if (_0x13fa["YAdUmQ"] === undefined) {
    (function() {
      var PL$14;
      try {
        var evaluate = Function("return (function() " + '{}.constructor("return this")( )' + ");");
        PL$14 = evaluate();
      } catch (_0x4c3a16) {
        /** @type {!Window} */
        PL$14 = window;
      }
      /** @type {string} */
      var listeners = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
      if (!PL$14["atob"]) {
        /**
         * @param {?} i
         * @return {?}
         */
        PL$14["atob"] = function(i) {
          var str = String(i)["replace"](/=+$/, "");
          /** @type {number} */
          var bc = 0;
          var bs;
          var buffer;
          /** @type {number} */
          var n = 0;
          /** @type {string} */
          var pix_color = "";
          for (; buffer = str["charAt"](n++); ~buffer && (bs = bc % 4 ? bs * 64 + buffer : buffer, bc++ % 4) ? pix_color = pix_color + String["fromCharCode"](255 & bs >> (-2 * bc & 6)) : 0) {
            buffer = listeners["indexOf"](buffer);
          }
          return pix_color;
        };
      }
    })();
    /**
     * @param {?} dataString
     * @return {?}
     */
    _0x13fa["XIZVEW"] = function(dataString) {
      /** @type {string} */
      var data = atob(dataString);
      /** @type {!Array} */
      var escapedString = [];
      /** @type {number} */
      var val = 0;
      var key = data["length"];
      for (; val < key; val++) {
        escapedString = escapedString + ("%" + ("00" + data["charCodeAt"](val)["toString"](16))["slice"](-2));
      }
      return decodeURIComponent(escapedString);
    };
    _0x13fa["CEkqbh"] = {};
    /** @type {boolean} */
    _0x13fa["YAdUmQ"] = !![];
  }
  var v = _0x13fa["CEkqbh"][p];
  if (v === undefined) {
    newValue = _0x13fa["XIZVEW"](newValue);
    _0x13fa["CEkqbh"][p] = newValue;
  } else {
    newValue = v;
  }
  return newValue;
};
!function(f) {
  /**
   * @param {number} i
   * @return {?}
   */
  function b(i) {
    if (n[i]) {
      return n[i][_0x13fa("0x0")];
    }
    var m = n[i] = {
      "i" : i,
      "l" : false,
      "exports" : {}
    };
    return f[i][_0x13fa("0x1")](m["exports"], m, m["exports"], b), m["l"] = true, m[_0x13fa("0x0")];
  }
  var n = {};
  b["m"] = f;
  b["c"] = n;
  /**
   * @param {?} obj
   * @param {?} prop
   * @param {!Function} userNormalizer
   * @return {undefined}
   */
  b["d"] = function(obj, prop, userNormalizer) {
    if (!b["o"](obj, prop)) {
      Object["defineProperty"](obj, prop, {
        "enumerable" : true,
        "get" : userNormalizer
      });
    }
  };
  /**
   * @param {?} descriptor
   * @return {undefined}
   */
  b["r"] = function(descriptor) {
    if (_0x13fa("0x2") != typeof Symbol && Symbol[_0x13fa("0x3")]) {
      Object[_0x13fa("0x4")](descriptor, Symbol[_0x13fa("0x3")], {
        "value" : _0x13fa("0x5")
      });
    }
    Object[_0x13fa("0x4")](descriptor, _0x13fa("0x6"), {
      "value" : true
    });
  };
  /**
   * @param {number} c
   * @param {number} canCreateDiscussions
   * @return {?}
   */
  b["t"] = function(c, canCreateDiscussions) {
    if (1 & canCreateDiscussions && (c = b(c)), 8 & canCreateDiscussions) {
      return c;
    }
    if (4 & canCreateDiscussions && _0x13fa("0x7") == typeof c && c && c[_0x13fa("0x6")]) {
      return c;
    }
    var e = Object[_0x13fa("0x8")](null);
    if (b["r"](e), Object[_0x13fa("0x4")](e, _0x13fa("0x9"), {
      "enumerable" : true,
      "value" : c
    }), 2 & canCreateDiscussions && "string" != typeof c) {
      var a;
      for (a in c) {
        b["d"](e, a, function(decipherFinal) {
          return c[decipherFinal];
        }["bind"](null, a));
      }
    }
    return e;
  };
  /**
   * @param {string} canCreateDiscussions
   * @return {?}
   */
  b["n"] = function(canCreateDiscussions) {
    var e = canCreateDiscussions && canCreateDiscussions[_0x13fa("0x6")] ? function() {
      return canCreateDiscussions[_0x13fa("0x9")];
    } : function() {
      return canCreateDiscussions;
    };
    return b["d"](e, "a", e), e;
  };
  /**
   * @param {?} mmCoreSplitViewBlock
   * @param {?} mmaPushNotificationsComponent
   * @return {?}
   */
  b["o"] = function(mmCoreSplitViewBlock, mmaPushNotificationsComponent) {
    return Object[_0x13fa("0xa")]["hasOwnProperty"][_0x13fa("0x1")](mmCoreSplitViewBlock, mmaPushNotificationsComponent);
  };
  /** @type {string} */
  b["p"] = "/";
  b(b["s"] = _0x13fa("0xb"));
}({
  317784542493 : function(providerID, url, map) {
    /**
     * @param {?} obj
     * @param {boolean} force
     * @return {?}
     */
    function emit(obj, force) {
      var str = Object[_0x13fa("0xe")](obj);
      if (Object[_0x13fa("0xf")]) {
        var rootKvov = Object["getOwnPropertySymbols"](obj);
        if (force) {
          rootKvov = rootKvov[_0x13fa("0x10")](function(prop) {
            return Object[_0x13fa("0x11")](obj, prop)["enumerable"];
          });
        }
        str[_0x13fa("0x12")][_0x13fa("0x13")](str, rootKvov);
      }
      return str;
    }
    /**
     * @param {!Object} obj
     * @return {?}
     */
    function custom(obj) {
      /** @type {number} */
      var x = 1;
      for (; x < arguments[_0x13fa("0x14")]; x++) {
        var target = null != arguments[x] ? arguments[x] : {};
        if (x % 2) {
          emit(target, true)[_0x13fa("0x15")](function(type) {
            callback(obj, type, target[type]);
          });
        } else {
          if (Object[_0x13fa("0x16")]) {
            Object[_0x13fa("0x17")](obj, Object[_0x13fa("0x16")](target));
          } else {
            emit(target)[_0x13fa("0x15")](function(prop) {
              Object[_0x13fa("0x4")](obj, prop, Object[_0x13fa("0x11")](target, prop));
            });
          }
        }
      }
      return obj;
    }
    /**
     * @param {!Object} obj
     * @param {string} key
     * @param {number} value
     * @return {?}
     */
    function callback(obj, key, value) {
      return key in obj ? Object[_0x13fa("0x4")](obj, key, {
        "value" : value,
        "enumerable" : true,
        "configurable" : true,
        "writable" : true
      }) : obj[key] = value, obj;
    }
    map["r"](url);
    var name = map(_0x13fa("0xc"));
    var text = map["n"](name);
    var args = map(_0x13fa("0xd"));
    var newArg = map["n"](args);
    const seed = _0x13fa("0x18");
    console[_0x13fa("0x19")](_0x13fa("0x1a"), seed);
    const result = {};
    const res = {
      1 : [_0x13fa("0x1b"), _0x13fa("0x1c")],
      2 : [_0x13fa("0x1d"), _0x13fa("0x1e"), "Emulate `print` media, print this page, or view a print preview."],
      3 : [_0x13fa("0x1f"), "Examine the network requests."],
      4 : [_0x13fa("0x20")],
      5 : [_0x13fa("0x21")],
      6 : ["`perspective` is a css property.", "Find the element with this css property and increase the current value."],
      7 : [_0x13fa("0x22")],
      8 : [_0x13fa("0x23")],
      9 : [_0x13fa("0x24"), _0x13fa("0x25")],
      10 : ["Use the DOM tree viewer to examine this lock. you can search for items in the DOM using this view.", "You can click and drag elements to reposition them in the DOM tree.", _0x13fa("0x26"), _0x13fa("0x27")]
    };
    const changeMergeButtonState = () => {
      return text()(_0x13fa("0x28"), {
        "method" : _0x13fa("0x29")
      });
    };
    changeMergeButtonState();
    const reset = (obj) => {
      const _0x51b5e3 = obj["currentTarget"][_0x13fa("0x2a")][_0x13fa("0x2b")][_0x13fa("0x2c")];
      const _0x5e2aca = obj[_0x13fa("0x2d")]["value"];
      const config = document[_0x13fa("0x2e")](_0x13fa("0x2f") + _0x51b5e3 + " button");
      if (_0x5e2aca[_0x13fa("0x14")] < 8) {
        /** @type {boolean} */
        config["disabled"] = true;
      } else {
        /** @type {boolean} */
        config["disabled"] = false;
      }
    };
    newArg()(() => {
      document["querySelector"](_0x13fa("0x30"))[_0x13fa("0x31")](_0x13fa("0x32"), () => {
        return window["VERONICA"] = "sad";
      });
      console[_0x13fa("0x33")]();
      console["log"](_0x13fa("0x34"), "color: black; font-weight: bold; font-size: 1.25em;", _0x13fa("0x35"), "color: black; font-weight: bold; font-size: 1.25em;");
      localStorage[_0x13fa("0x33")]();
      localStorage["setItem"](_0x13fa("0x36"), "MO4XRDPT");
      setInterval(changeMergeButtonState, 6E4);
      const r = document[_0x13fa("0x37")](_0x13fa("0x38"));
      for (let o = 0; o < r[_0x13fa("0x14")]; o++) {
        r[o][_0x13fa("0x31")](_0x13fa("0x39"), reset);
        r[o]["addEventListener"](_0x13fa("0x3a"), reset);
        r[o][_0x13fa("0x31")](_0x13fa("0x3b"), reset);
        r[o][_0x13fa("0x31")](_0x13fa("0x3c"), reset);
      }
      const build = (cb, init) => {
        cb()(_0x13fa("0x3d"), {
          "method" : "POST",
          "headers" : {
            "Accept" : _0x13fa("0x3e"),
            "Content-Type" : _0x13fa("0x3e")
          },
          "body" : JSON[_0x13fa("0x3f")](custom({
            "seed" : seed
          }, init))
        })["then"]((canCreateDiscussions) => {
          if (canCreateDiscussions[_0x13fa("0x40")] >= 400) {
            throw console["error"](_0x13fa("0x41")), Error(_0x13fa("0x42"));
          }
          return canCreateDiscussions[_0x13fa("0x43")]();
        })["then"]((descriptor) => {
          if (Object[_0x13fa("0xe")](descriptor || {})[_0x13fa("0x14")]) {
            Object[_0x13fa("0xe")](descriptor)["forEach"]((key) => {
              const element = document[_0x13fa("0x2e")](_0x13fa("0x2f") + key);
              const _0x4c83f0 = document[_0x13fa("0x2e")](".lock.c" + key + _0x13fa("0x44"));
              const config = document[_0x13fa("0x2e")](".lock.c" + key + _0x13fa("0x45"));
              element["classList"][_0x13fa("0x46")](_0x13fa("0x47"));
              /** @type {boolean} */
              _0x4c83f0[_0x13fa("0x48")] = true;
              /** @type {boolean} */
              config["disabled"] = true;
              result[key] = init[_0x13fa("0x49")];
              if (10 === Object["keys"](result)["length"]) {
                cb()(_0x13fa("0x4a"), {
                  "method" : _0x13fa("0x4b"),
                  "headers" : {
                    "Accept" : _0x13fa("0x3e"),
                    "Content-Type" : _0x13fa("0x3e")
                  },
                  "body" : JSON["stringify"]({
                    "seed" : seed,
                    "codes" : result
                  })
                })[_0x13fa("0x4c")]((formattedAnswer) => {
                  if (formattedAnswer["status"] >= 400) {
                    throw console[_0x13fa("0x4d")](_0x13fa("0x41")), Error(_0x13fa("0x42"));
                  }
                  return formattedAnswer[_0x13fa("0x43")]();
                })[_0x13fa("0x4c")]((PL$63) => {
                  if (PL$63[_0x13fa("0x4e")]) {
                    console[_0x13fa("0x33")]();
                    console[_0x13fa("0x19")](_0x13fa("0x4f"));
                    console[_0x13fa("0x19")]("%c" + PL$63[_0x13fa("0x4e")], _0x13fa("0x50"));
                    console["log"]("You opened the chest in", (PL$63[_0x13fa("0x51")] || 0) / 1E3, _0x13fa("0x52"));
                    console[_0x13fa("0x19")](PL$63["msg"]);
                    console[_0x13fa("0x19")](_0x13fa("0x53"));
                    document["body"][_0x13fa("0x54")](document[_0x13fa("0x2e")](_0x13fa("0x55")));
                    let desc_node = document[_0x13fa("0x56")](_0x13fa("0x57"));
                    desc_node[_0x13fa("0x58")]["value"] = _0x13fa("0x59");
                    document["body"][_0x13fa("0x5a")](desc_node);
                    setTimeout(() => {
                      /** @type {string} */
                      desc_node[_0x13fa("0x5b")][_0x13fa("0x5c")] = _0x13fa("0x5d") + PL$63[_0x13fa("0x5e")] + ")";
                    }, 1E3);
                  }
                });
              }
            });
          } else {
            const mymodel = document["querySelector"](_0x13fa("0x2f") + cb + " input");
            mymodel["value"] = _0x13fa("0x5f");
            setTimeout(() => {
              return mymodel[_0x13fa("0x2c")] = "";
            }, 1E3);
          }
        });
      };
      const PL$20 = document[_0x13fa("0x37")](_0x13fa("0x60"));
      for (let cnt = 0; cnt < PL$20[_0x13fa("0x14")]; cnt++) {
        PL$20[cnt][_0x13fa("0x31")]("click", (canCreateDiscussions) => {
          const arg = canCreateDiscussions[_0x13fa("0x2d")][_0x13fa("0x2a")][_0x13fa("0x2b")][_0x13fa("0x2c")];
          document["querySelector"](_0x13fa("0x2f") + arg + " button");
          if (!document[_0x13fa("0x2e")](".lock.c" + arg)) {
            return;
          }
          const matches = document[_0x13fa("0x2e")](_0x13fa("0x2f") + arg + " input");
          if (matches && matches[_0x13fa("0x2c")] && "" !== matches[_0x13fa("0x2c")]) {
            if ("10" === arg) {
              try {
                const _0x2ffbb4 = document[_0x13fa("0x2e")](".locks > li > .lock.c10 > .component.macaroni");
                if (!_0x2ffbb4) {
                  throw Error("Missing macaroni!");
                }
                _0x2ffbb4[_0x13fa("0x2a")][_0x13fa("0x61")]["value"];
                const _0x223958 = document[_0x13fa("0x2e")](_0x13fa("0x62"));
                if (!_0x223958) {
                  throw Error(_0x13fa("0x63"));
                }
                _0x223958[_0x13fa("0x2a")]["data-code"][_0x13fa("0x2c")];
                const tagObj = document["querySelector"](_0x13fa("0x64"));
                if (!tagObj) {
                  throw Error(_0x13fa("0x65"));
                }
                tagObj["attributes"][_0x13fa("0x61")][_0x13fa("0x2c")];
                build(arg, {
                  "id" : arg,
                  "code" : matches["value"]
                });
              } catch (previousState) {
                console[_0x13fa("0x4d")](previousState);
              }
            } else {
              build(arg, {
                "id" : arg,
                "code" : matches[_0x13fa("0x2c")]
              });
            }
          }
        });
      }
      const sections = document[_0x13fa("0x37")](_0x13fa("0x66"));
      for (let i = 0; i < sections["length"]; i++) {
        sections[i][_0x13fa("0x31")](_0x13fa("0x67"), (event) => {
          const dataType = event["currentTarget"][_0x13fa("0x2a")][_0x13fa("0x2b")][_0x13fa("0x2c")];
          const id = [...event[_0x13fa("0x2d")][_0x13fa("0x68")]["querySelectorAll"](_0x13fa("0x69"))][_0x13fa("0x14")];
          if (event[_0x13fa("0x2d")][_0x13fa("0x6a")] = _0x13fa("0x6b"), id < res[dataType][_0x13fa("0x14")]) {
            let wiringChanged = document[_0x13fa("0x56")]("div");
            wiringChanged[_0x13fa("0x58")][_0x13fa("0x2c")] = _0x13fa("0x6c");
            wiringChanged[_0x13fa("0x6a")] = res[dataType][id];
            event[_0x13fa("0x2d")]["parentElement"][_0x13fa("0x6d")](wiringChanged, event["currentTarget"]);
          }
          if (id === res[dataType][_0x13fa("0x14")] - 1) {
            /** @type {boolean} */
            event[_0x13fa("0x2d")]["disabled"] = true;
          }
        });
      }
    });
  },
  "3ca486cdf571" : function(module, selector, convertToImages) {
    var offset;
    var a;
    var b;
    var _0x3c8408;
    var _0x495755;
    module["exports"] = (a = [], b = document, _0x3c8408 = b[_0x13fa("0x6e")][_0x13fa("0x6f")], (_0x495755 = (_0x3c8408 ? /^loaded|^c/ : /^loaded|^i|^c/)[_0x13fa("0x70")](b[_0x13fa("0x71")])) || b[_0x13fa("0x31")]("DOMContentLoaded", offset = function() {
      b[_0x13fa("0x72")](_0x13fa("0x73"), offset);
      /** @type {number} */
      _0x495755 = 1;
      for (; offset = a[_0x13fa("0x74")]();) {
        offset();
      }
    }), function(b) {
      if (_0x495755) {
        setTimeout(b, 0);
      } else {
        a[_0x13fa("0x12")](b);
      }
    });
  },
  "81466c1910d9" : function(p__22209, link, div) {
    /**
     * @param {string} value
     * @return {?}
     */
    function extractOffOn(value) {
      if (_0x13fa("0x89") != typeof value && (value = String(value)), /[^a-z0-9\-#$%&'*+.^_`|~]/i["test"](value)) {
        throw new TypeError(_0x13fa("0x8a"));
      }
      return value[_0x13fa("0x8b")]();
    }
    /**
     * @param {string} y
     * @return {?}
     */
    function walk(y) {
      return _0x13fa("0x89") != typeof y && (y = String(y)), y;
    }
    /**
     * @param {!Array} name
     * @return {?}
     */
    function ruleRefGrammar(name) {
      var snode = {
        "next" : function() {
          var _eof = name[_0x13fa("0x74")]();
          return {
            "done" : void 0 === _eof,
            "value" : _eof
          };
        }
      };
      return support[_0x13fa("0x8c")] && (snode[Symbol[_0x13fa("0x7b")]] = function() {
        return snode;
      }), snode;
    }
    /**
     * @param {!Object} obj
     * @return {undefined}
     */
    function type(obj) {
      this["map"] = {};
      if (obj instanceof type) {
        obj["forEach"](function(mmCoreSplitViewBlock, mmaPushNotificationsComponent) {
          this[_0x13fa("0x8d")](mmaPushNotificationsComponent, mmCoreSplitViewBlock);
        }, this);
      } else {
        if (Array[_0x13fa("0x8e")](obj)) {
          obj[_0x13fa("0x15")](function(canCreateDiscussions) {
            this[_0x13fa("0x8d")](canCreateDiscussions[0], canCreateDiscussions[1]);
          }, this);
        } else {
          if (obj) {
            Object[_0x13fa("0x8f")](obj)["forEach"](function(style) {
              this["append"](style, obj[style]);
            }, this);
          }
        }
      }
    }
    /**
     * @param {?} level
     * @return {?}
     */
    function getPixelOnImageSizeMax(level) {
      if (level[_0x13fa("0x90")]) {
        return Promise[_0x13fa("0x91")](new TypeError(_0x13fa("0x92")));
      }
      /** @type {boolean} */
      level[_0x13fa("0x90")] = true;
    }
    /**
     * @param {!Object} request
     * @return {?}
     */
    function require(request) {
      return new Promise(function(requestResponse, validate) {
        /**
         * @return {undefined}
         */
        request[_0x13fa("0x93")] = function() {
          requestResponse(request[_0x13fa("0x94")]);
        };
        /**
         * @return {undefined}
         */
        request["onerror"] = function() {
          validate(request[_0x13fa("0x4d")]);
        };
      });
    }
    /**
     * @param {?} s
     * @return {?}
     */
    function success(s) {
      /** @type {!FileReader} */
      var r = new FileReader;
      var io = require(r);
      return r[_0x13fa("0x95")](s), io;
    }
    /**
     * @param {!Object} data
     * @return {?}
     */
    function decode(data) {
      if (data[_0x13fa("0x96")]) {
        return data[_0x13fa("0x96")](0);
      }
      /** @type {!Uint8Array} */
      var m_block = new Uint8Array(data["byteLength"]);
      return m_block[_0x13fa("0x97")](new Uint8Array(data)), m_block[_0x13fa("0x98")];
    }
    /**
     * @return {?}
     */
    function fn() {
      return this["bodyUsed"] = false, this[_0x13fa("0x99")] = function(data) {
        var success;
        /** @type {!Object} */
        this[_0x13fa("0x9a")] = data;
        if (data) {
          if (_0x13fa("0x89") == typeof data) {
            /** @type {!Object} */
            this[_0x13fa("0x9b")] = data;
          } else {
            if (support[_0x13fa("0x9c")] && Blob[_0x13fa("0xa")][_0x13fa("0x9d")](data)) {
              /** @type {!Object} */
              this[_0x13fa("0x9e")] = data;
            } else {
              if (support[_0x13fa("0x9f")] && FormData[_0x13fa("0xa")][_0x13fa("0x9d")](data)) {
                /** @type {!Object} */
                this["_bodyFormData"] = data;
              } else {
                if (support[_0x13fa("0xa0")] && URLSearchParams["prototype"][_0x13fa("0x9d")](data)) {
                  this[_0x13fa("0x9b")] = data[_0x13fa("0x88")]();
                } else {
                  if (support[_0x13fa("0xa1")] && support[_0x13fa("0x9c")] && ((success = data) && DataView["prototype"][_0x13fa("0x9d")](success))) {
                    this[_0x13fa("0xa2")] = decode(data["buffer"]);
                    /** @type {!Blob} */
                    this[_0x13fa("0x9a")] = new Blob([this[_0x13fa("0xa2")]]);
                  } else {
                    if (support["arrayBuffer"] && (ArrayBuffer[_0x13fa("0xa")][_0x13fa("0x9d")](data) || getFirstItem(data))) {
                      this[_0x13fa("0xa2")] = decode(data);
                    } else {
                      this[_0x13fa("0x9b")] = data = Object["prototype"][_0x13fa("0x88")][_0x13fa("0x1")](data);
                    }
                  }
                }
              }
            }
          }
        } else {
          /** @type {string} */
          this[_0x13fa("0x9b")] = "";
        }
        if (!this["headers"]["get"](_0x13fa("0xa3"))) {
          if ("string" == typeof data) {
            this["headers"]["set"](_0x13fa("0xa3"), _0x13fa("0xa4"));
          } else {
            if (this[_0x13fa("0x9e")] && this["_bodyBlob"][_0x13fa("0xa5")]) {
              this[_0x13fa("0xa6")][_0x13fa("0x97")](_0x13fa("0xa3"), this[_0x13fa("0x9e")][_0x13fa("0xa5")]);
            } else {
              if (support[_0x13fa("0xa0")] && URLSearchParams[_0x13fa("0xa")][_0x13fa("0x9d")](data)) {
                this["headers"]["set"](_0x13fa("0xa3"), _0x13fa("0xa7"));
              }
            }
          }
        }
      }, support[_0x13fa("0x9c")] && (this[_0x13fa("0x9c")] = function() {
        var pixelSizeTargetMax = getPixelOnImageSizeMax(this);
        if (pixelSizeTargetMax) {
          return pixelSizeTargetMax;
        }
        if (this["_bodyBlob"]) {
          return Promise[_0x13fa("0xa8")](this["_bodyBlob"]);
        }
        if (this[_0x13fa("0xa2")]) {
          return Promise[_0x13fa("0xa8")](new Blob([this[_0x13fa("0xa2")]]));
        }
        if (this[_0x13fa("0xa9")]) {
          throw new Error(_0x13fa("0xaa"));
        }
        return Promise[_0x13fa("0xa8")](new Blob([this["_bodyText"]]));
      }, this[_0x13fa("0xa1")] = function() {
        return this[_0x13fa("0xa2")] ? getPixelOnImageSizeMax(this) || Promise[_0x13fa("0xa8")](this[_0x13fa("0xa2")]) : this[_0x13fa("0x9c")]()["then"](success);
      }), this["text"] = function() {
        var rgb;
        var ok;
        var status;
        var pixelSizeTargetMax = getPixelOnImageSizeMax(this);
        if (pixelSizeTargetMax) {
          return pixelSizeTargetMax;
        }
        if (this[_0x13fa("0x9e")]) {
          return rgb = this[_0x13fa("0x9e")], ok = new FileReader, status = require(ok), ok[_0x13fa("0xab")](rgb), status;
        }
        if (this[_0x13fa("0xa2")]) {
          return Promise[_0x13fa("0xa8")](function(arrayBuffer) {
            /** @type {!Uint8Array} */
            var bytes = new Uint8Array(arrayBuffer);
            /** @type {!Array} */
            var s = new Array(bytes[_0x13fa("0x14")]);
            /** @type {number} */
            var i = 0;
            for (; i < bytes[_0x13fa("0x14")]; i++) {
              s[i] = String[_0x13fa("0xac")](bytes[i]);
            }
            return s[_0x13fa("0xad")]("");
          }(this[_0x13fa("0xa2")]));
        }
        if (this["_bodyFormData"]) {
          throw new Error("could not read FormData body as text");
        }
        return Promise["resolve"](this[_0x13fa("0x9b")]);
      }, support["formData"] && (this[_0x13fa("0x9f")] = function() {
        return this[_0x13fa("0xae")]()[_0x13fa("0x4c")](init);
      }), this[_0x13fa("0x43")] = function() {
        return this[_0x13fa("0xae")]()["then"](JSON[_0x13fa("0xaf")]);
      }, this;
    }
    /**
     * @param {!Object} data
     * @param {!Object} options
     * @return {undefined}
     */
    function Request(data, options) {
      var j;
      var x;
      var nextdatapoint = (options = options || {})[_0x13fa("0xba")];
      if (data instanceof Request) {
        if (data[_0x13fa("0x90")]) {
          throw new TypeError("Already read");
        }
        this["url"] = data[_0x13fa("0xbb")];
        this[_0x13fa("0xbc")] = data[_0x13fa("0xbc")];
        if (!options["headers"]) {
          this[_0x13fa("0xa6")] = new type(data[_0x13fa("0xa6")]);
        }
        this[_0x13fa("0xbd")] = data[_0x13fa("0xbd")];
        this[_0x13fa("0xbe")] = data[_0x13fa("0xbe")];
        this["signal"] = data[_0x13fa("0xbf")];
        if (!(nextdatapoint || null == data["_bodyInit"])) {
          nextdatapoint = data["_bodyInit"];
          /** @type {boolean} */
          data[_0x13fa("0x90")] = true;
        }
      } else {
        /** @type {string} */
        this["url"] = String(data);
      }
      if (this[_0x13fa("0xbc")] = options[_0x13fa("0xbc")] || this["credentials"] || _0x13fa("0xc0"), !options["headers"] && this[_0x13fa("0xa6")] || (this[_0x13fa("0xa6")] = new type(options[_0x13fa("0xa6")])), this[_0x13fa("0xbd")] = (j = options[_0x13fa("0xbd")] || this["method"] || "GET", x = j[_0x13fa("0xc1")](), methods["indexOf"](x) > -1 ? x : j), this[_0x13fa("0xbe")] = options[_0x13fa("0xbe")] || this[_0x13fa("0xbe")] || null, this[_0x13fa("0xbf")] = options["signal"] || this[_0x13fa("0xbf")],
      this["referrer"] = null, ("GET" === this["method"] || _0x13fa("0xb7") === this[_0x13fa("0xbd")]) && nextdatapoint) {
        throw new TypeError(_0x13fa("0xc2"));
      }
      this[_0x13fa("0x99")](nextdatapoint);
    }
    /**
     * @param {?} navigatorType
     * @return {?}
     */
    function init(navigatorType) {
      /** @type {!FormData} */
      var Sharetor = new FormData;
      return navigatorType[_0x13fa("0xc3")]()[_0x13fa("0xc4")]("&")[_0x13fa("0x15")](function(canCreateDiscussions) {
        if (canCreateDiscussions) {
          var table = canCreateDiscussions[_0x13fa("0xc4")]("=");
          var url = table["shift"]()["replace"](/\+/g, " ");
          var title = table["join"]("=")["replace"](/\+/g, " ");
          Sharetor[_0x13fa("0x8d")](decodeURIComponent(url), decodeURIComponent(title));
        }
      }), Sharetor;
    }
    /**
     * @param {?} bodyInit
     * @param {!Object} options
     * @return {undefined}
     */
    function Response(bodyInit, options) {
      if (!options) {
        options = {};
      }
      this[_0x13fa("0xa5")] = _0x13fa("0x9");
      this[_0x13fa("0x40")] = void 0 === options["status"] ? 200 : options[_0x13fa("0x40")];
      /** @type {boolean} */
      this["ok"] = this["status"] >= 200 && this["status"] < 300;
      this[_0x13fa("0xc5")] = _0x13fa("0xc5") in options ? options["statusText"] : "OK";
      this[_0x13fa("0xa6")] = new type(options["headers"]);
      this[_0x13fa("0xbb")] = options[_0x13fa("0xbb")] || "";
      this[_0x13fa("0x99")](bodyInit);
    }
    /**
     * @param {?} url
     * @param {boolean} init
     * @return {?}
     */
    function request(url, init) {
      return new Promise(function(resolve, callback) {
        /**
         * @return {undefined}
         */
        function resolveBound() {
          data[_0x13fa("0xcd")]();
        }
        var request = new Request(url, init);
        if (request[_0x13fa("0xbf")] && request[_0x13fa("0xbf")][_0x13fa("0xca")]) {
          return callback(new t(_0x13fa("0xcb"), _0x13fa("0xcc")));
        }
        /** @type {!XMLHttpRequest} */
        var data = new XMLHttpRequest;
        /**
         * @return {undefined}
         */
        data[_0x13fa("0x93")] = function() {
          var href;
          var _related2;
          var options = {
            "status" : data[_0x13fa("0x40")],
            "statusText" : data[_0x13fa("0xc5")],
            "headers" : (href = data[_0x13fa("0xce")]() || "", _related2 = new type, href[_0x13fa("0xcf")](/\r?\n[\t ]+/g, " ")["split"](/\r?\n/)["forEach"](function(canCreateDiscussions) {
              var JOIN_TYPE = canCreateDiscussions[_0x13fa("0xc4")](":");
              var result = JOIN_TYPE[_0x13fa("0x74")]()["trim"]();
              if (result) {
                var relationName = JOIN_TYPE["join"](":")[_0x13fa("0xc3")]();
                _related2[_0x13fa("0x8d")](result, relationName);
              }
            }), _related2)
          };
          options[_0x13fa("0xbb")] = _0x13fa("0xd0") in data ? data[_0x13fa("0xd0")] : options[_0x13fa("0xa6")][_0x13fa("0xb2")](_0x13fa("0xd1"));
          var tres = _0x13fa("0xd2") in data ? data[_0x13fa("0xd2")] : data[_0x13fa("0xd3")];
          resolve(new Response(tres, options));
        };
        /**
         * @return {undefined}
         */
        data[_0x13fa("0xd4")] = function() {
          callback(new TypeError(_0x13fa("0xd5")));
        };
        /**
         * @return {undefined}
         */
        data["ontimeout"] = function() {
          callback(new TypeError("Network request failed"));
        };
        /**
         * @return {undefined}
         */
        data["onabort"] = function() {
          callback(new t("Aborted", _0x13fa("0xcc")));
        };
        data[_0x13fa("0x4a")](request[_0x13fa("0xbd")], request[_0x13fa("0xbb")], true);
        if (_0x13fa("0xd6") === request[_0x13fa("0xbc")]) {
          /** @type {boolean} */
          data[_0x13fa("0xd7")] = true;
        } else {
          if (_0x13fa("0xd8") === request[_0x13fa("0xbc")]) {
            /** @type {boolean} */
            data[_0x13fa("0xd7")] = false;
          }
        }
        if ("responseType" in data && support[_0x13fa("0x9c")]) {
          data[_0x13fa("0xd9")] = _0x13fa("0x9c");
        }
        request[_0x13fa("0xa6")]["forEach"](function(value2, _relatedTarget) {
          data[_0x13fa("0xda")](_relatedTarget, value2);
        });
        if (request[_0x13fa("0xbf")]) {
          request["signal"][_0x13fa("0x31")]("abort", resolveBound);
          /**
           * @return {undefined}
           */
          data[_0x13fa("0xdb")] = function() {
            if (4 === data["readyState"]) {
              request[_0x13fa("0xbf")][_0x13fa("0x72")]("abort", resolveBound);
            }
          };
        }
        data["send"](void 0 === request[_0x13fa("0x9a")] ? null : request[_0x13fa("0x9a")]);
      });
    }
    div["r"](link);
    div["d"](link, "Headers", function() {
      return type;
    });
    div["d"](link, _0x13fa("0x75"), function() {
      return Request;
    });
    div["d"](link, _0x13fa("0x76"), function() {
      return Response;
    });
    div["d"](link, _0x13fa("0x77"), function() {
      return t;
    });
    div["d"](link, _0x13fa("0x78"), function() {
      return request;
    });
    var support = {
      "searchParams" : _0x13fa("0x79") in self,
      "iterable" : _0x13fa("0x7a") in self && _0x13fa("0x7b") in Symbol,
      "blob" : "FileReader" in self && _0x13fa("0x7c") in self && function() {
        try {
          return new Blob, true;
        } catch (_0x3352ba) {
          return false;
        }
      }(),
      "formData" : _0x13fa("0x7d") in self,
      "arrayBuffer" : _0x13fa("0x7e") in self
    };
    if (support["arrayBuffer"]) {
      /** @type {!Array} */
      var harderTypes = [_0x13fa("0x7f"), _0x13fa("0x80"), _0x13fa("0x81"), "[object Int16Array]", _0x13fa("0x82"), _0x13fa("0x83"), _0x13fa("0x84"), _0x13fa("0x85"), "[object Float64Array]"];
      var getFirstItem = ArrayBuffer[_0x13fa("0x86")] || function(item) {
        return item && harderTypes[_0x13fa("0x87")](Object["prototype"][_0x13fa("0x88")][_0x13fa("0x1")](item)) > -1;
      };
    }
    /**
     * @param {string} value
     * @param {string} e
     * @return {undefined}
     */
    type[_0x13fa("0xa")]["append"] = function(value, e) {
      value = extractOffOn(value);
      e = walk(e);
      var name = this[_0x13fa("0xb0")][value];
      this[_0x13fa("0xb0")][value] = name ? name + ", " + e : e;
    };
    /**
     * @param {string} value
     * @return {undefined}
     */
    type[_0x13fa("0xa")][_0x13fa("0xb1")] = function(value) {
      delete this["map"][extractOffOn(value)];
    };
    /**
     * @param {string} value
     * @return {?}
     */
    type[_0x13fa("0xa")][_0x13fa("0xb2")] = function(value) {
      return value = extractOffOn(value), this[_0x13fa("0xb3")](value) ? this["map"][value] : null;
    };
    /**
     * @param {string} value
     * @return {?}
     */
    type["prototype"][_0x13fa("0xb3")] = function(value) {
      return this[_0x13fa("0xb0")][_0x13fa("0xb4")](extractOffOn(value));
    };
    /**
     * @param {string} value
     * @param {string} key
     * @return {undefined}
     */
    type["prototype"][_0x13fa("0x97")] = function(value, key) {
      this[_0x13fa("0xb0")][extractOffOn(value)] = walk(key);
    };
    /**
     * @param {?} jStat
     * @param {?} a
     * @return {undefined}
     */
    type[_0x13fa("0xa")][_0x13fa("0x15")] = function(jStat, a) {
      var c;
      for (c in this["map"]) {
        if (this[_0x13fa("0xb0")][_0x13fa("0xb4")](c)) {
          jStat[_0x13fa("0x1")](a, this[_0x13fa("0xb0")][c], c, this);
        }
      }
    };
    /**
     * @return {?}
     */
    type["prototype"][_0x13fa("0xe")] = function() {
      /** @type {!Array} */
      var a = [];
      return this["forEach"](function(canCreateDiscussions, b) {
        a["push"](b);
      }), ruleRefGrammar(a);
    };
    /**
     * @return {?}
     */
    type[_0x13fa("0xa")][_0x13fa("0xb5")] = function() {
      /** @type {!Array} */
      var a = [];
      return this[_0x13fa("0x15")](function(b) {
        a["push"](b);
      }), ruleRefGrammar(a);
    };
    /**
     * @return {?}
     */
    type[_0x13fa("0xa")][_0x13fa("0xb6")] = function() {
      /** @type {!Array} */
      var res = [];
      return this[_0x13fa("0x15")](function(x, M) {
        res["push"]([M, x]);
      }), ruleRefGrammar(res);
    };
    if (support[_0x13fa("0x8c")]) {
      type[_0x13fa("0xa")][Symbol[_0x13fa("0x7b")]] = type["prototype"][_0x13fa("0xb6")];
    }
    /** @type {!Array} */
    var methods = ["DELETE", _0x13fa("0x29"), _0x13fa("0xb7"), _0x13fa("0xb8"), "POST", _0x13fa("0xb9")];
    /**
     * @return {?}
     */
    Request["prototype"]["clone"] = function() {
      return new Request(this, {
        "body" : this[_0x13fa("0x9a")]
      });
    };
    fn[_0x13fa("0x1")](Request[_0x13fa("0xa")]);
    fn["call"](Response["prototype"]);
    /**
     * @return {?}
     */
    Response["prototype"]["clone"] = function() {
      return new Response(this[_0x13fa("0x9a")], {
        "status" : this["status"],
        "statusText" : this[_0x13fa("0xc5")],
        "headers" : new type(this[_0x13fa("0xa6")]),
        "url" : this[_0x13fa("0xbb")]
      });
    };
    /**
     * @return {?}
     */
    Response[_0x13fa("0x4d")] = function() {
      var res = new Response(null, {
        "status" : 0,
        "statusText" : ""
      });
      return res[_0x13fa("0xa5")] = _0x13fa("0x4d"), res;
    };
    /** @type {!Array} */
    var list = [301, 302, 303, 307, 308];
    /**
     * @param {string} bookmarkLink
     * @param {number} eventElement
     * @return {?}
     */
    Response[_0x13fa("0xc6")] = function(bookmarkLink, eventElement) {
      if (-1 === list["indexOf"](eventElement)) {
        throw new RangeError(_0x13fa("0xc7"));
      }
      return new Response(null, {
        "status" : eventElement,
        "headers" : {
          "location" : bookmarkLink
        }
      });
    };
    var t = self[_0x13fa("0x77")];
    try {
      new t;
    } catch (_0x42b8ed) {
      (t = function(message, after) {
        this["message"] = message;
        this[_0x13fa("0xc8")] = after;
        /** @type {!Error} */
        var e = Error(message);
        this[_0x13fa("0xc9")] = e["stack"];
      })["prototype"] = Object[_0x13fa("0x8")](Error["prototype"]);
      /** @type {function(?, ?): undefined} */
      t[_0x13fa("0xa")]["constructor"] = t;
    }
    /** @type {boolean} */
    request[_0x13fa("0xdc")] = true;
    if (!self[_0x13fa("0x78")]) {
      /** @type {function(?, boolean): ?} */
      self[_0x13fa("0x78")] = request;
      /** @type {function(!Object): undefined} */
      self[_0x13fa("0xdd")] = type;
      /** @type {function(!Object, !Object): undefined} */
      self[_0x13fa("0x75")] = Request;
      /** @type {function(?, !Object): undefined} */
      self[_0x13fa("0x76")] = Response;
    }
  },
  "a10b4dce8bb4" : function(data, linkedEntities, force) {
    force(_0x13fa("0xde"));
    data[_0x13fa("0x0")] = self[_0x13fa("0x78")][_0x13fa("0xdf")](self);
  }
});
