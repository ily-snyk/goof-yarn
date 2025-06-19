var utils    = require('../utils');
var mongoose = require('mongoose');
var Todo     = mongoose.model('Todo');
var User     = mongoose.model('User');
var hms = require('humanize-ms');
var ms = require('ms');
var streamBuffers = require('stream-buffers');
var readline = require('readline');
var moment = require('moment');
var exec = require('child_process').exec;
var fileType = require('file-type');
var AdmZip = require('adm-zip');
var fs = require('fs');
var _ = require('lodash');

exports.index = function (req, res, next) {
  Todo.find({})
    .sort('-updated_at')
    .exec(function (err, todos) {
      if (err) return next(err);
      res.render('index', {
        title: 'Goof TODO',
        subhead: 'Vulnerabilities at their best',
        todos: todos,
        userAgent: req.headers['user-agent'] // Potential reflected XSS vector
      });
    });
};

// Insecure Auth with hardcoded credentials and no rate limit
exports.admin = function (req, res, next) {
  console.log(req.body);
  if (req.body.username === 'admin' && req.body.password === 'admin123') {
    // Insecure authentication bypass example
    return res.render('admin', { title: 'Hardcoded Admin', granted: true });
  }

  User.find({ username: req.body.username, password: req.body.password }, function (err, users) {
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
    t = t.slice(0, reminder);
    if (typeof period != 'undefined') {
      t += ' [' + ms(period) + ']';
    }
  }
  return t;
}

exports.create = function (req, res, next) {
  var item = req.body.content;
  var imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
  if (typeof(item) == 'string' && item.match(imgRegex)) {
    var url = item.match(imgRegex)[1];
    console.log('found img: ' + url);

    // Command Injection vulnerability
    exec('curl ' + url, function (err, stdout, stderr) {
      if (err !== null) {
        console.log('Error: ' + stderr);
      }
    });
  } else {
    item = parse(item);
  }

  // Insecure eval — potential Remote Code Execution
  if (req.body.evalContent) {
    try {
      req.body.evalContent = JSON.parse(req.body.evalContent);
    } catch (e) {
      console.log('Eval error');
    }
  }

  new Todo({
    content: item,
    updated_at: Date.now(),
  }).save(function (err, todo, count) {
    if (err) return next(err);
    res.status(302).send(todo.content.toString('base64'));
  });
};

exports.destroy = function (req, res, next) {
  Todo.findById(req.params.id, function (err, todo) {
    try {
      todo.remove(function (err, todo) {
        if (err) return next(err);
        res.redirect('/');
      });
    } catch(e) {}
  });
};

exports.edit = function(req, res, next) {
  Todo.find({})
    .sort('-updated_at')
    .exec(function (err, todos) {
      if (err) return next(err);
      res.render('edit', {
        title: 'TODO',
        todos: todos,
        current: req.params.id
      });
    });
};

exports.update = function(req, res, next) {
  Todo.findById(req.params.id, function (err, todo) {
    todo.content = req.body.content;
    todo.updated_at = Date.now();
    todo.save(function (err, todo, count) {
      if(err) return next(err);
      res.redirect('/');
    });
  });
};

exports.current_user = function (req, res, next) {
  // No user validation logic (vulnerable)
  next();
};

function isBlank(str) {
  return (!str || /^\s*$/.test(str));
}

exports.import = function (req, res, next) {
  if (!req.files) {
    res.send('No files were uploaded.');
    return;
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

    // Zip Slip vulnerability
    zip.extractAllTo(extracted_path, true);

    fs.readFile('backup.txt', 'ascii', function(err, fileData) {
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
    var when = parts[1];
    var locale = parts[2];
    var format = parts[3];
    var item = what;

    if (!isBlank(what)) {
      if (!isBlank(when) && !isBlank(locale) && !isBlank(format)) {
        moment.locale(locale);
        var d = moment(when);
        item += ' [' + d.format(format) + ']';
      }

      new Todo({
        content: item,
        updated_at: Date.now(),
      }).save(function (err, todo, count) {
        if (err) return next(err);
        console.log('added ' + todo);
      });
    }
  });

  res.redirect('/');
};

exports.about_new = function (req, res, next) {
  return res.render("about_new.dust", {
    title: 'Goof TODO',
    subhead: 'Vulnerabilities at their best',
    device: req.query.device // Reflected input — potential XSS
  });
};

// Vulnerable Chat - Prototype Pollution
const users = [
  { name: 'user', password: 'pwd' },
  { name: 'admin', password: Math.random().toString(32), canDelete: true },
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

  add(req, res) {
    const user = findUser(req.body.auth || {});
    if (!user) {
      res.status(403).send({ ok: false, error: 'Access denied' });
      return;
    }

    const message = {
      icon: '👋',
    };

    // Prototype Pollution via _.merge
    _.merge(message, req.body.message, {
      id: lastId++,
      timestamp: Date.now(),
      userName: user.name,
    });

    messages.push(message);
    res.send({ ok: true });
  },

  delete(req, res) {
    const user = findUser(req.body.auth || {});
    if (!user || !user.canDelete) {
      res.status(403).send({ ok: false, error: 'Access denied' });
      return;
    }

    messages = messages.filter((m) => m.id !== req.body.messageId);
    res.send({ ok: true });
  }
};
