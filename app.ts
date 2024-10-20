/**
 * @param {import('probot').Probot} app
 */

// import * as Octokit from "@octokit/rest";
//import * as Utils from "./config/global-utils";
const { Octokit } = require("@octokit/rest");
const OctoKitfetch = require("node-fetch");
const Utils = require("./config/global-utils.ts")

const octokit = new Octokit({
  auth: process.env.GITHUB_TOKEN, request: {
    fetch: OctoKitfetch,
  },
});

module.exports = (app) => {
  app.log("Yay! The app was loaded!");

  const workflowName = ["Snyk Bot scan", "TruffleHog Bot scan", "Bot scan"];

  app.on("issues.opened", async (context) => {
    app.log("Yay! The new issues opened!");
    return context.octokit.issues.createComment(
      context.issue({ body: "Hello, World!" })
    );
  });

  // app.on(["pull_request.opened", "pull_request.reopened"], async (context) => {
  app.onAny(async (context) => {
    app.log.info("Yay!, The New Pull-Request is opened / reopened!");

    const user = Utils.getCurrentUser(context);
    let truffleOutput = "",
      snykOutput = "";

    const { owner, repo } = context.repo();

    // Get the workflows for the repository
    const response = await octokit.rest.actions.listWorkflowRunsForRepo({
      owner,
      repo,
    });

    app.log(`response: ${response}`);
    // Iterate over the workflow runs and retrieve error details
    const workflowRuns = response.data.workflow_runs
      .filter(
        (w) =>
          workflowName.includes(w.name) &&
          // w.conclusion === "failure" &&
          w.event === "pull_request_target"
      );
    app.log(`workflowRuns: ${workflowRuns}`);

    for (const run of workflowRuns) {
      app.log(`run1.event : ${run.event}`);
      // if (run.conclusion === "failure" && run.event === "pull_request_target") {
      if (run.event === "pull_request_target") {
        app.log(`run2.event : ${run.event}`);
        const jobsResponse = await octokit.rest.actions.listJobsForWorkflowRun({
          owner,
          repo,
          run_id: run.id,
        });
        app.log(`jobsResponse: ${jobsResponse}`);
        app.log(`jobsResponse.data.jobs: ${jobsResponse.data.jobs}`);

        // Iterate over jobs and find the failed step
        for (const job of jobsResponse.data.jobs) {
          const jobDetails = await octokit.rest.actions.getJobForWorkflowRun({
            owner,
            repo,
            job_id: job.id,
          });
          app.log(`jobDetails: ${jobDetails}`);

          const steps = jobDetails.data.steps.filter((w) =>
            workflowName.includes(w.name)
          );
          app.log(`steps: ${steps}`);
          const { conclusion } = jobDetails.data;
          app.log(`conclusion: ${conclusion}`);
          if (conclusion === "failure" || conclusion === "success") {
            for (const step of steps) {
              if (
                // (step.conclusion === "failure" ||
                //   step.conclusion === "skipped") &&
                Utils.checkStringContains(step.name, "truffle")
                //   &&
                // step.conclusion === "success" && conclusion === "success"
              ) {
                // Retrieve the response of the failed step
                const logResponse =
                  await octokit.rest.actions.downloadJobLogsForWorkflowRun({
                    owner,
                    repo,
                    job_id: job.id,
                  });

                let truffleLogOutput = logResponse.data;

                truffleOutput = Utils.parseLogOutput(truffleLogOutput, "truffle");
                truffleOutput = truffleLogOutput;
                // } else if (conclusion === "failure" &&
                //   (step.conclusion === "failure" ||
                //     step.conclusion === "skipped") &&
                //   Utils.checkStringContains(step.name, "snyk") &&
                //   step.conclusion != "success"
                // ) {
              } else if (Utils.checkStringContains(step.name, "snyk")
              ) {
                // Retrieve the response of the failed step
                const logResponse =
                  await octokit.rest.actions.downloadJobLogsForWorkflowRun({
                    owner,
                    repo,
                    job_id: job.id,
                  });

                let snykLogOutput = logResponse.data;
                // snykOutput = Utils.parseLogOutput(snykLogOutput, "snyk");
                snykOutput = snykLogOutput;
              }
            }
          }
        }
      }
    }

    let truffleSecrets =
      "<h3>Secrets Bot</h3>\n" +
      (truffleOutput === ""
        ? `<i>All good in the hood no uncovered secrets found in raised Pull-Request.</i>`
        : truffleOutput);
    let snykSecrets =
      "<h3>SCA Bot</h3> \n" +
      (snykOutput === ""
        ? `<i>All good in the hood no vulnerable package found in raised Pull-Request.</i>`
        : snykOutput);

    const msg = context.issue({
      body:
        `Hey @${user} 👋, Thanks for contributing the new Pull Request !!` +
        truffleSecrets +
        snykSecrets +
        Utils.footer,
    });

    return context.octokit.issues.createComment(msg);
  });
};
