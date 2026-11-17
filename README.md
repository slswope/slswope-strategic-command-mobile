# Strategic Command

A mobile dashboard for National Weather Service alerts in Evansville, Newburgh, and Henderson, plus the CISA Known Exploited Vulnerabilities catalog. The other monitoring tracks show their coverage status. The original workbook is stored separately and should stay private.

## Deployment

The workflow runs the Python tests, checks the public feeds, and deploys the `site/` directory. In repository Settings → Pages, select **GitHub Actions** as the publishing source. Run **Strategic Command — official feeds and iPhone dashboard** from the Actions tab on `main` to publish on demand. The workflow also runs on pushes to `main` and is scheduled roughly every 30 minutes.

Open the URL listed in Settings → Pages in Safari. To add the dashboard to an iPhone Home Screen, use **Share → Add to Home Screen**.

The dashboard marks data stale after 95 minutes. Follow official emergency alerts and look at the feed status for any failed checks. The CISA catalog lists known exploited vulnerabilities. Consult official incident reporting for active cyber incidents.

## Foreign developments

The dated briefing is stored in `site/foreign.json` and published with the site. Review new entries against primary notices and reputable reporting. Label shared sourcing and unresolved details, and include U.S. relevance and the next observable development. Update `reviewed_on` only after a review. The weather and vulnerability refresh schedule does not update the briefing. Only public information belongs in this file.

## Optional notifications

To send newly seen high-priority NWS alerts through Pushover, create the repository Actions secrets `PUSHOVER_APP_TOKEN` and `PUSHOVER_USER_KEY`. Use GitHub's secret fields for credentials. The workflow stores previously sent public alert IDs in `state/notified.json` to avoid repeat alerts.

## Local verification

Run `python3 -m unittest discover -s tests -v` for the rule tests. Run `python3 scripts/update.py` to check live feeds, then serve the dashboard with `python3 -m http.server --directory site`.

## Sources

- [National Weather Service alerts API](https://www.weather.gov/documentation/services-web-alerts)
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [GitHub Pages publishing source](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
