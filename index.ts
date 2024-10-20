import { run } from "@probot/adapter-github-actions";
import app from "./app.ts";

run(app).catch((error) => {
  console.error(error);
  process.exit(1);
});
