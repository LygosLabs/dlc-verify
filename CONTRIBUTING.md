# Contributing to DLC Verify

Thank you for your interest in contributing to DLC Verify! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

- Node.js 18+
- pnpm (recommended)

### Getting Started

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/dlc-verify.git
   cd dlc-verify
   ```

2. Install dependencies:
   ```bash
   pnpm install
   ```

3. Build the project:
   ```bash
   pnpm run build
   ```

4. Run the development server:
   ```bash
   pnpm start
   # Open http://localhost:3456
   ```

## Running Tests

Run the test suite before submitting changes:

```bash
pnpm test
```

For development with watch mode:

```bash
pnpm test:watch
```

## Linting

This project uses [Biome](https://biomejs.dev/) for linting and formatting.

Check for linting issues:

```bash
pnpm lint
```

Auto-fix linting issues:

```bash
pnpm lint:fix
```

## Pull Request Process

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and ensure:
   - Tests pass (`pnpm test`)
   - Linting passes (`pnpm lint`)
   - Code builds successfully (`pnpm run build`)

3. Write clear, descriptive commit messages

4. Push your branch and open a Pull Request against `main`

5. Describe your changes in the PR description, including:
   - What the change does
   - Why it's needed
   - Any breaking changes or migration steps

## Code Style

- TypeScript for all source code
- Follow existing patterns in the codebase
- Keep functions focused and well-named
- Add tests for new functionality

## Questions?

Feel free to open an issue for questions, bug reports, or feature requests.
