## [0.2.1] - 2026-09-28

### 🚀 Features

- *(cli)* Add hash command (#13)

### 🐛 Bug Fixes

- *(cli)* Show matched hash in query plain and table output (#27)
- *(cli)* Exit successfully on zero query results (#28)
- *(source)* Propagate I/O errors instead of silently stopping (#26)
- *(source)* Reject HTTP error responses in UrlSource (#25)

### 📚 Documentation

- Standardize badges

### 🚜 Refactor

- *(cli)* Extract shared R2Args (#15)

### ⚙️ Miscellaneous Tasks

- Add `deepwiki` badge
## [0.2.0] - 2025-12-30

### 🚀 Features

- *(cli)* Show available algorithms in --algo help text (#7)
- *(cli)* Add --quiet flag to suppress progress output (#8)
- *(cli)* Add --dry-run flag to build command (#9)
- *(cli)* Add result count summary to query output (#5) (#10)

### 🧪 Testing

- *(source)* Add unit tests for UrlSource (#6)

### ⚙️ Miscellaneous Tasks

- *(release)* V0.2.0
## [0.1.0] - 2025-12-28

### 🚀 Features

- Initial implementation of hash database builder

### 📚 Documentation

- Add configuration section and roadmap

### ⚙️ Miscellaneous Tasks

- Add Arch Linux packaging and AUR workflow
- Add crates.io publish workflow
- Add justfile with release automation
- *(release)* V0.1.0
