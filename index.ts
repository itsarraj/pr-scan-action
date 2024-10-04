const { run } = require("@probot/adapter-github-actions");
const botApp = require("./app");

run(botApp);