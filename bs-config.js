module.exports = {
  proxy: "http://localhost:3004",
  files: ["public/**/*.{css,js}", "views/**/*.pug"],
  reloadDelay: 1000,
  open: false, // Prevents the browser from opening
};
