# Scorecard Certifier

The Scorecard Certifier is a component that generates scorecard attestations for repositories. It uses the [OpenSSF Scorecard](https://github.com/ossf/scorecard) to evaluate the security posture of a repository.

## How It Works

### Initialization

The `NewScorecardCertifier` function initializes the scorecard certifier. It checks if the `GITHUB_AUTH_TOKEN` is set in the environment. If not, it returns an error. The token is used to access the GitHub API.

### Certifying Components

The `CertifyComponent` function takes a `source.SourceNode` as input and generates a scorecard attestation. It uses the `GetScore` function to retrieve the scorecard data for the repository.

### Using the Scorecard Library and GitHub Auth Token

The `GetScore` function first checks if the `useScorecardAPI` flag is set to `true`. If it is, it calls the Scorecard API to retrieve the scorecard data. If the API call fails, it uses the Scorecard library and the GitHub auth token to retrieve the scorecard data.

### Using the Scorecard API

The Scorecard API is a public API that provides access to scorecard data. It can be used to retrieve scorecard data for any repository, regardless of whether the user has access to the GitHub repository. However, the API might fail if the repository does not exist in its database.

### Differences

The main difference between using the GitHub auth token/Scorecard library and the Scorecard API is that the GitHub auth token/Scorecard library requires access to the GitHub repository, while the Scorecard API does not.

The Scorecard API is also more efficient than using the GitHub auth token/Scorecard library, as it does not need to download the entire repository.

If the `useScorecardAPI` flag is not set, or the Scorecard API call fails, the certifier will default to using the GitHub auth token/Scorecard library.