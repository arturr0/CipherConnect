// bs-config.js
module.exports = {
  proxy: "http://localhost:3004",
  files: ["public/**/*.{html,css,js}", "views/**/*.pug"],
  port: 3000,
  open: false,
  reloadDelay: 0, // Ensure no delay
  notify: false, // Disable notifications for simplicity
};
