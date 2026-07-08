package remediator

import "encoding/json"

// findFrameDocJS is a shared helper prepended to every script below. The
// router admin UI is a FRAMESET, and chromedp's element/selector actions
// cannot reliably target elements inside child frames on this router. Instead
// every script below runs entirely inside chromedp.Evaluate and walks
// window.frames itself (same-origin, so document access across frames is
// allowed) to find the frame document matching a predicate.
const findFrameDocJS = `
function __wdFindFrameDoc(win, predicate, depth) {
  depth = depth || 0;
  if (depth > 6) return null;
  try {
    var doc = win.document;
    if (doc && predicate(doc)) return doc;
  } catch (e) {}
  var frames;
  try {
    frames = win.frames;
  } catch (e) {
    return null;
  }
  if (!frames) return null;
  for (var i = 0; i < frames.length; i++) {
    var found = null;
    try {
      found = __wdFindFrameDoc(frames[i], predicate, depth + 1);
    } catch (e) {
      found = null;
    }
    if (found) return found;
  }
  return null;
}
`

// loginScriptTemplate finds the login frame (identified by
// input[name=Password]), sets the password, and clicks the submit button
// (value "Entrar"). A real .click() triggers the router's own native form
// submit, which is the only way observed to actually authenticate against
// this router (see engram dns-modem-watchdog/remediation-approach).
//
// %s is replaced with a JSON-encoded JS string literal for the password, so
// the value is safely embedded regardless of its contents. The password is
// never included in any log line produced by this package.
const loginScriptTemplate = findFrameDocJS + `
(function() {
  var doc = __wdFindFrameDoc(window, function(d) {
    return d.querySelector('input[name="Password"]') !== null;
  });
  if (!doc) return 'error: login frame not found';
  var pwInput = doc.querySelector('input[name="Password"]');
  pwInput.value = %s;
  var submit = null;
  var candidates = doc.querySelectorAll('input[type="submit"]');
  for (var i = 0; i < candidates.length; i++) {
    if (!submit) submit = candidates[i];
    if (candidates[i].value && candidates[i].value.indexOf('Entrar') !== -1) {
      submit = candidates[i];
      break;
    }
  }
  if (!submit) return 'error: submit button not found';
  submit.click();
  return 'ok';
})()
`

// readLANScriptTemplate finds the LAN configuration frame (identified by
// input[name=DNSserver1]) and returns its current DNS values as JSON. When no
// such frame is found (e.g. login did not authenticate and the page bounced
// back to the login form), authenticated is reported false.
const readLANScriptTemplate = findFrameDocJS + `
(function() {
  var doc = __wdFindFrameDoc(window, function(d) {
    return d.querySelector('input[name="DNSserver1"]') !== null;
  });
  if (!doc) {
    return JSON.stringify({ authenticated: false, dnsServer1: '', dnsServer2: '' });
  }
  var dns1 = doc.querySelector('input[name="DNSserver1"]');
  var dns2 = doc.querySelector('input[name="DNSserver2"]');
  return JSON.stringify({
    authenticated: true,
    dnsServer1: dns1 ? dns1.value : '',
    dnsServer2: dns2 ? dns2.value : ''
  });
})()
`

// setDNSScriptTemplate finds the LAN configuration frame, sets DNSserver1 and
// DNSserver2 to the desired value, and clicks the "Aplicar cambios" button
// (an input[type=button] whose value contains "Aplicar").
//
// %s / %s are replaced with JSON-encoded JS string literals for
// DNSserver1/DNSserver2 respectively.
const setDNSScriptTemplate = findFrameDocJS + `
(function() {
  var doc = __wdFindFrameDoc(window, function(d) {
    return d.querySelector('input[name="DNSserver1"]') !== null;
  });
  if (!doc) return 'error: LAN frame not found';
  var dns1 = doc.querySelector('input[name="DNSserver1"]');
  var dns2 = doc.querySelector('input[name="DNSserver2"]');
  if (!dns1 || !dns2) return 'error: DNS inputs not found';
  dns1.value = %s;
  dns2.value = %s;
  var applyBtn = null;
  var buttons = doc.querySelectorAll('input[type="button"]');
  for (var i = 0; i < buttons.length; i++) {
    if (buttons[i].value && buttons[i].value.indexOf('Aplicar') !== -1) {
      applyBtn = buttons[i];
      break;
    }
  }
  if (!applyBtn) return 'error: apply button not found';
  applyBtn.click();
  return 'ok';
})()
`

// lanPageValues is the JSON shape returned by readLANScriptTemplate.
type lanPageValues struct {
	Authenticated bool   `json:"authenticated"`
	DNSServer1    string `json:"dnsServer1"`
	DNSServer2    string `json:"dnsServer2"`
}

// jsStringLiteral JSON-encodes s so it can be safely spliced into a JS
// script as a string literal (handles quotes, backslashes, unicode, etc.).
func jsStringLiteral(s string) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
