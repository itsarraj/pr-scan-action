import { run } from "@probot/adapter-github-actions";

run(app).catch((error) => {
  console.error(error);
  process.exit(1);
});
