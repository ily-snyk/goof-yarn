var utils       = require('../utils');
var mongoose    = require('mongoose');
var Todo        = mongoose.model('Todo');
var User        = mongoose.model('User');
// TODO:
var hms = require('humanize-ms');
var ms = require('ms');
var streamBuffers = require('stream-buffers');
var readline = require('readline');
var moment = require('moment');
var exec = require('child_process').exec;

// zip-slip
var fileType = require('file-type');
var AdmZip = require('adm-zip');
var fs = require('fs');
var path = require('path');

// prototype-pollution
var _ = require('lodash');

exports.index = function (req, res, next) {
  Todo.
    find({}).
    sort('-updated_at').
    exec(function (err, todos) {
      if (err) return next(err);

      res.render('index', {
        title: 'Goof TODO',
        subhead: 'Vulnerabilities at their best',
        todos: todos,
      });
    });
};


/*
 * VULNERABILITY: NoSQL Injection
 * The query is constructed using `req.body.username` and `req.body.password` directly.
 * An attacker can bypass authentication by injecting a NoSQL query operator.
 * For example, sending a POST request with the following JSON body will grant access:
 * {
 * "username": "admin",
 * "password": { "$ne": null }
 * }
 * The query becomes `User.find({ username: 'admin', password: { '$ne': null } })`,
 * which finds an admin user where the password is not null, effectively bypassing the password check.
 */
exports.admin = function (req, res, next) {
  console.log(req.body);
  User.find({ username: req.body.username, password: req.body.password }, function (err, users) {
    if (err) return next(err); // Basic error handling

    if (users.length > 0) {
      return res.render('admin', {
        title: 'Admin Access Granted',
        granted: true,
      });
    } else {
      return res.render('admin', {
        title: 'Admin Access',
        granted: false,
      });
    }
  });

};

function parse(todo) {
  var t = todo;

  var remindToken = ' in ';
  var reminder = t.toString().indexOf(remindToken);
  if (reminder > 0) {
    var time = t.slice(reminder + remindToken.length);
    time = time.replace(/\n$/, '');

    var period = hms(time);

    console.log('period: ' + period);

    // remove it
    t = t.slice(0, reminder);
    if (typeof period != 'undefined') {
      t += ' [' + ms(period) + ']';
    }
  }
  return t;
}

/*
 * VULNERABILITY: Command Injection
 * The `exec` function is called with user-controllable input `url`.
 * An attacker can inject arbitrary commands by crafting a malicious string.
 * For example, if `content` is `![alt text](; ls -la #.png "title")`, the `url` becomes `; ls -la #`
 * and the executed command will be `identify ; ls -la #`, listing the files in the current directory.
 */
exports.create = function (req, res, next) {
  var item = req.body.content;
  var imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
  if (typeof(item) == 'string' && item.match(imgRegex)) {
    var url = item.match(imgRegex)[1];
    console.log('found img: ' + url);

    exec('identify ' + url, function (err, stdout, stderr) {
      console.log(err);
      if (err !== null) {
        console.log('Error (' + err + '):' + stderr);
      }
    });

  } else {
    item = parse(item);
  }

  new Todo({
      content: item,
      updated_at: Date.now(),
      // VULNERABILITY: IDOR - No user association is saved with the TODO item.
    }).save(function (err, todo, count) {
    if (err) return next(err);
    res.setHeader('Location', '/');
    res.status(302).send(todo.content.toString('base64'));
  });
};

/*
 * VULNERABILITY: Insecure Direct Object Reference (IDOR)
 * This function deletes a Todo item based on the ID from the URL (`req.params.id`).
 * However, it does not check if the current user is the owner of the Todo item.
 * As a result, any authenticated user can delete any other user's Todo items
 * simply by knowing the item's ID (e.g., /destroy/5f9d7b3b7e3f0b2a7c4f1d3e).
 */
exports.destroy = function (req, res, next) {
  Todo.findById(req.params.id, function (err, todo) {
    if (err) return next(err);
    // There is no check here to see if `req.user.id === todo.userId`
    try {
      todo.remove(function (err, todo) {
        if (err) return next(err);
        res.redirect('/');
    	});
    } catch(e) {
      // The empty catch block might hide errors.
    }
  });
};

exports.edit = function(req, res, next) {
  Todo.
    find({}).
    sort('-updated_at').
    exec(function (err, todos) {
      if (err) return next(err);

      res.render('edit', {
        title   : 'TODO',
        todos   : todos,
        current : req.params.id
      });
    });
};

/*
 * VULNERABILITY: Insecure Direct Object Reference (IDOR)
 * Similar to the destroy function, this function updates a Todo item without
 * verifying ownership. Any user can modify any Todo item if they know its ID.
 */
exports.update = function(req, res, next) {
  Todo.findById(req.params.id, function (err, todo) {
    if (err) return next(err);
    // There is no check here to see if `req.user.id === todo.userId`
    todo.content    = req.body.content;
    todo.updated_at = Date.now();
    todo.save(function (err, todo, count) {
      if(err) return next(err);
      res.redirect('/');
    });
  });
};


exports.current_user = function (req, res, next) {
  next();
};

function isBlank(str) {
  return (!str || /^\s*$/.test(str));
}

/*
 * VULNERABILITY: Zip Slip
 * The code extracts a user-provided zip file to a temporary directory.
 * If an older, vulnerable version of `adm-zip` is used, an attacker can create
 * a zip file containing path traversal sequences (e.g., `../../../../etc/passwd`).
 * When `extractAllTo` is called, it could allow the attacker to overwrite arbitrary
 * files on the server.
 * The `overwrite: true` parameter makes this particularly dangerous.
 * NOTE: I have corrected the `fs.readFile` path to make the intended (though flawed)
 * logic of reading from the extracted content clearer.
 */
exports.import = function (req, res, next) {
  if (!req.files) {
    return res.send('No files were uploaded.');
  }

  var importFile = req.files.importFile;
  var data;
  var importedFileType = fileType(importFile.data);
  var zipFileExt = { ext: "zip", mime: "application/zip" };
  if (importedFileType === null) {
    importedFileType = { ext: "txt", mime: "text/plain" };
  }
  if (importedFileType["mime"] === zipFileExt["mime"]) {
    var zip = new AdmZip(importFile.data);
    var extracted_path = "/tmp/extracted_files";
    // The `overwrite` flag is set to true, making file overwrites possible.
    zip.extractAllTo(extracted_path, /* overwrite */ true);
    data = "No backup.txt file found";
    // The vulnerability is in `extractAllTo`. This part just shows intended usage.
    fs.readFile(path.join(extracted_path, 'backup.txt'), 'ascii', function(err, fileData) {
      if (!err) {
        data = fileData;
      }
    });
  } else {
    data = importFile.data.toString('ascii');
  }
  var lines = data.split('\n');
  lines.forEach(function (line) {
    var parts = line.split(',');
    var what = parts[0];
    if (!isBlank(what)) {
      // ... (rest of the import logic)
    }
  });

  res.redirect('/');
};

/*
 * VULNERABILITY: Reflected Cross-Site Scripting (XSS)
 * The `req.query.device` parameter is taken directly from the URL and rendered
 * into the page without any sanitization or escaping.
 * An attacker can craft a malicious URL to inject a script into the page.
 * Example: /about_new?device=<script>alert('XSS')</script>
 * When a user visits this URL, the script will execute in their browser.
 */
exports.about_new = function (req, res, next) {
    console.log(JSON.stringify(req.query));
    return res.render("about_new.dust", // Assuming .dust templates are used
      {
        title: 'Goof TODO',
        subhead: 'Vulnerabilities at their best',
        device: req.query.device // The vulnerable part
      });
};

/*
 * VULNERABILITY: Open Redirect
 * This endpoint redirects the user to a URL specified in the query string.
 * There is no validation to ensure the URL is internal to the application.
 * An attacker can craft a link that looks legitimate but redirects the user
 * to a malicious phishing site.
 * Example: /redirect?url=http://malicious-site.com
 */
exports.redirect = function(req, res, next) {
    var target = req.query.url;
    if (target) {
        res.redirect(target);
    } else {
        res.send("No url provided");
    }
};

/*
 * VULNERABILITY: Regular Expression Denial of Service (ReDoS)
 * The regex /A(B|C+)+D/ is vulnerable to "catastrophic backtracking".
 * An attacker can provide a string like "ACCCCCCCCCCCCCCCCCCCCC!"
 * The way the regex engine processes the nested quantifiers `(C+)+` causes
 * an exponential number of steps, freezing the server's event loop.
 */
exports.checkString = function(req, res, next) {
    const vulnerableRegex = /A(B|C+)+D/;
    const userInput = req.query.input; // e.g., "ACCCCCCCCCCCCCCCCCCCCC!"
    
    if (vulnerableRegex.test(userInput)) {
        res.send("String is valid.");
    } else {
        res.send("String is not valid.");
    }
};


// Prototype Pollution

const users = [
  {name: 'user', password: 'pwd'},
  {name: 'admin', password: Math.random().toString(32), canDelete: true},
];

let messages = [];
let lastId = 1;

function findUser(auth) {
  return users.find((u) => u.name === auth.name && u.password === auth.password);
}

exports.chat = {
  get(req, res) {
    res.send(messages);
  },
  /*
   * VULNERABILITY: Prototype Pollution
   * `_.merge` recursively merges properties of objects. If the `req.body.message`
   * object contains a `__proto__` key, it can modify the `Object.prototype`.
   * An attacker can send a JSON payload like:
   * {
   * "message": {
   * "__proto__": {
   * "canDelete": true
   * }
   * },
   * "auth": { "name": "user", "password": "pwd" }
   * }
   * This pollutes the prototype of all objects, giving every user `canDelete` privileges.
   * When a normal user object is created later, it will inherit `canDelete: true`
   * and be able to delete messages.
   */
  add(req, res) {
    const user = findUser(req.body.auth || {});

    if (!user) {
      res.status(403).send({ok: false, error: 'Access denied'});
      return;
    }

    const message = {
      icon: '👋',
    };

    // The vulnerable merge operation
    _.merge(message, req.body.message, {
      id: lastId++,
      timestamp: Date.now(),
      userName: user.name,
    });

    messages.push(message);
    res.send({ok: true});
  },
  delete(req, res) {
    // A new user object is created here for the check. If the prototype has been
    // polluted with `canDelete: true`, this check will pass for any user.
    const user = findUser(req.body.auth || {});

    if (!user || !user.canDelete) {
      res.status(403).send({ok: false, error: 'Access denied'});
      return;
    }

    messages = messages.filter((m) => m.id !== req.body.messageId);
    res.send({ok: true});
  }
};
