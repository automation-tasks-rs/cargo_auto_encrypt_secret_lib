// automation_tasks_rs for encrypt_secret

// for projects that don't use github, delete all the mentions of GitHub
mod github_mod;

// region: library with basic automation tasks
use cargo_auto_github_lib as cgl;
use cargo_auto_lib as cl;

use cgl::SendToGitHubApi;
// traits must be in scope (Rust strangeness)
use cl::CargoTomlPublicApiMethods;

use cl::GREEN;
use cl::RED;
use cl::RESET;
use cl::YELLOW;
fn main() {
    std::panic::set_hook(Box::new(|panic_info| panic_set_hook(panic_info)));

    cl::exit_if_not_run_in_rust_project_root_directory();

    // get CLI arguments
    let mut args = std::env::args();
    // the zero argument is the name of the program
    let _arg_0 = args.next();
    match_arguments_and_call_tasks(args);
}

/// The report of the panic is ugly for the user
///
/// I use panics extensively to stop the execution. I am lazy to implement a super complicated error handling.
/// I just need to stop the execution on every little bit of error. This utility is for developers. They will understand me.
/// For errors I print the location. For not-error exit the location is not important.
fn panic_set_hook(panic_info: &std::panic::PanicInfo) {
    let mut string_message = "".to_string();
    if let Some(message) = panic_info.payload().downcast_ref::<String>() {
        string_message = message.to_owned();
    }
    if let Some(message) = panic_info.payload().downcast_ref::<&str>() {
        string_message.push_str(message);
    }

    eprintln!("{string_message}");

    if !string_message.contains("Exiting:") {
        let file = panic_info.location().unwrap().file();
        let line = panic_info.location().unwrap().line();
        let column = panic_info.location().unwrap().column();
        eprintln!("Location: {file}:{line}:{column}");
    }
}

// region: match, help and completion

/// match arguments and call tasks functions
fn match_arguments_and_call_tasks(mut args: std::env::Args) {
    // the first argument is the user defined task: (no argument for help), build, release,...
    let arg_1 = args.next();
    match arg_1 {
        None => print_help(),
        Some(task) => {
            if &task == "completion" {
                completion();
            } else {
                println!("{YELLOW}Running automation task: {task}{RESET}");
                if &task == "build" {
                    task_build();
                } else if &task == "release" {
                    task_release();
                } else if &task == "doc" {
                    task_doc();
                } else if &task == "test" {
                    task_test();
                } else if &task == "commit_and_push" {
                    let arg_2 = args.next();
                    task_commit_and_push(arg_2);
                } else if &task == "publish_to_crates_io" {
                    task_publish_to_crates_io();
                } else if &task == "github_new_release" {
                    task_github_new_release();
                } else {
                    eprintln!("{RED}Error: Task {task} is unknown.{RESET}");
                    print_help();
                }
            }
        }
    }
}

/// write a comprehensible help for user defined tasks
fn print_help() {
    println!(
        r#"
    {YELLOW}Welcome to cargo-auto !{RESET}
    {YELLOW}This program automates your custom tasks when developing a Rust project.{RESET}

    {YELLOW}User defined tasks in automation_tasks_rs:{RESET}
{GREEN}cargo auto build{RESET} - {YELLOW}builds the crate in debug mode, fmt, increment version{RESET}
{GREEN}cargo auto release{RESET} - {YELLOW}builds the crate in release mode, fmt, increment version{RESET}
{GREEN}cargo auto doc{RESET} - {YELLOW}builds the docs, copy to docs directory{RESET}
{GREEN}cargo auto test{RESET} - {YELLOW}runs all the tests{RESET}
{GREEN}cargo auto commit_and_push "message"{RESET} - {YELLOW}commits with message and push with mandatory message{RESET}
    {YELLOW}It is preferred to use SSH for git push to GitHub.{RESET}
    {YELLOW}<https://github.com/CRUSTDE-ContainerizedRustDevEnv/crustde_cnt_img_pod/blob/main/ssh_easy.md>{YELLOW}
    {YELLOW}On the very first commit, this task will initialize a new local git repository and create a remote GitHub repo.{RESET}
    {YELLOW}For the Github API the task needs the Personal Access Token Classic from <https://github.com/settings/tokens>{RESET}
    {YELLOW}You can choose to type the token every time or to store it in a file encrypted with an SSH key.{RESET}
    {YELLOW}Then you can write the passphrase of the private key every time ot store the private key in ssh-agent for the current session.{RESET}
{GREEN}cargo auto publish_to_crates_io{RESET} - {YELLOW}publish to crates.io, git tag{RESET}
    {YELLOW}You need the API token for publishing. Get the token on <https://crates.io/settings/tokens>.{RESET}
    {YELLOW}You can choose to type the token every time or to store it in a file encrypted with an SSH key.{RESET}
    {YELLOW}Then you can write the passphrase of the private key every time ot store the private key in ssh-agent for the current session.{RESET}

{GREEN}cargo auto github_new_release{RESET} - {YELLOW}creates new release on github{RESET}
    {YELLOW}For the Github API the task needs the Personal Access Token Classic from <https://github.com/settings/tokens>{RESET}
    {YELLOW}You can choose to type the token every time or to store it in a file encrypted with an SSH key.{RESET}
    {YELLOW}Then you can write the passphrase of the private key every time ot store the private key in ssh-agent for the current session.{RESET}

    {YELLOW}© 2024 bestia.dev  MIT License github.com/automation-tasks-rs/cargo-auto{RESET}
"#
    );
    print_examples_cmd();
}

/// all example commands in one place
fn print_examples_cmd() {
    println!(
        r#"
    {YELLOW}run examples:{RESET}
{GREEN}cargo run --example encrypt_to_file{RESET}
{GREEN}cargo run --example decrypt_from_file{RESET}
"#
    );
}

/// sub-command for bash auto-completion of `cargo auto` using the crate `dev_bestia_cargo_completion`
fn completion() {
    let args: Vec<String> = std::env::args().collect();
    let word_being_completed = args[2].as_str();
    let last_word = args[3].as_str();

    if last_word == "cargo-auto" || last_word == "auto" {
        let sub_commands = vec!["build", "release", "doc", "test", "commit_and_push", "publish_to_crates_io", "github_new_release"];
        cl::completion_return_one_or_more_sub_commands(sub_commands, word_being_completed);
    }
    /*
    // the second level if needed
    else if last_word == "new" {
        let sub_commands = vec!["x"];
       cl::completion_return_one_or_more_sub_commands(sub_commands, word_being_completed);
    }
    */
}

// endregion: match, help and completion

// region: tasks

/// cargo build
fn task_build() {
    //    let cargo_toml = cl::CargoToml::read();
    cl::auto_version_increment_semver_or_date();
    cl::run_shell_command("cargo fmt");
    cl::run_shell_command("cargo build");
    println!(
        r#"
    {YELLOW}After `cargo auto build`, examples and/or tests{RESET}
    {YELLOW}if ok then{RESET}
{GREEN}cargo auto release{RESET}
"#,
        // package_name = cargo_toml.package_name(),
    );
    print_examples_cmd();
}

/// cargo build --release
fn task_release() {
    // let cargo_toml = cl::CargoToml::read();
    cl::auto_version_increment_semver_or_date();
    cl::auto_cargo_toml_to_md();
    cl::auto_lines_of_code("");

    cl::run_shell_command("cargo fmt");
    cl::run_shell_command("cargo build --release");
    println!(
        r#"
    {YELLOW}After `cargo auto release`, run examples and/or tests{RESET}
    {YELLOW}if ok then{RESET}
{GREEN}cargo auto doc{RESET}
"#,
        // package_name = cargo_toml.package_name(),
    );
    print_examples_cmd();
}

/// cargo doc, then copies to /docs/ folder, because this is a github standard folder
fn task_doc() {
    let cargo_toml = cl::CargoToml::read();
    cl::auto_cargo_toml_to_md();
    cl::auto_lines_of_code("");
    // we have sample data that we don't want to change, so I comment this line:
    // cl::auto_plantuml(&cargo_toml.package_repository().unwrap());
    // we have sample data that we don't want to change, so I comment this line:
    // cl::auto_playground_run_code();
    cl::auto_md_to_doc_comments();

    cl::run_shell_command("cargo doc --no-deps --document-private-items");
    // copy target/doc into docs/ because it is github standard
    cl::run_shell_command("rsync -a --info=progress2 --delete-after target/doc/ docs/");
    // Create simple index.html file in docs directory
    cl::run_shell_command(&format!(
        r#"printf "<meta http-equiv=\"refresh\" content=\"0; url={}/index.html\" />\n" > docs/index.html"#,
        cargo_toml.package_name().replace("-", "_")
    ));
    // pretty html
    cl::auto_doc_tidy_html().unwrap();
    cl::run_shell_command("cargo fmt");
    // message to help user with next move
    println!(
        r#"
    {YELLOW}After `cargo auto doc`, ctrl-click on `docs/index.html`. 
    It will show the index.html in VSCode Explorer, then right-click and choose "Show Preview".
    This works inside the CRUSTDE container, because of the extension "Live Preview" 
    <https://marketplace.visualstudio.com/items?itemName=ms-vscode.live-server>
    If ok then run the tests in code and the documentation code examples.{RESET}
{GREEN}cargo auto test{RESET}
"#
    );
}

/// cargo test
fn task_test() {
    cl::run_shell_command("cargo test");
    println!(
        r#"
    {YELLOW}After `cargo auto test`. If ok then {RESET}
    {YELLOW}(commit message is mandatory){RESET}
{GREEN}cargo auto commit_and_push "message"{RESET}
"#
    );
}

/// commit and push
fn task_commit_and_push(arg_2: Option<String>) {
    let Some(message) = arg_2 else {
        eprintln!("{RED}Error: Message for commit is mandatory.{RESET}");
        // early exit
        return;
    };

    // If needed, ask to create new local git repository
    if !cl::git_is_local_repository() {
        cl::new_local_repository(&message).unwrap();
    }

    // If needed, ask to create a GitHub remote repository
    if !cl::git_has_remote() {
        let github_client = crate::github_mod::GitHubClient::new();
        cgl::new_remote_github_repository(&github_client).unwrap();
        cgl::description_and_topics_to_github(&github_client);
    } else {
        let github_client = crate::github_mod::GitHubClient::new();
        // if description or topics/keywords/tags have changed
        cgl::description_and_topics_to_github(&github_client);

        // separate commit for docs if they changed, to not make a lot of noise in the real commit
        if std::path::Path::new("docs").exists() {
            cl::run_shell_command(r#"git add docs && git diff --staged --quiet || git commit -m "update docs" "#);
        }

        cl::add_message_to_unreleased(&message);
        // the real commit of code
        cl::run_shell_command(&format!(r#"git add -A && git diff --staged --quiet || git commit -m "{message}" "#));
        cl::run_shell_command("git push");
    }

    println!(
        r#"
{YELLOW}After `cargo auto commit_and_push "message"`{RESET}
{GREEN}cargo auto publish_to_crates_io{RESET}
"#
    );
}

/// publish to crates.io and git tag
fn task_publish_to_crates_io() {
    let cargo_toml = cl::CargoToml::read();
    let package_name = cargo_toml.package_name();
    let version = cargo_toml.package_version();
    // take care of tags
    let tag_name_version = cl::git_tag_sync_check_create_push(&version);

    // cargo publish with encrypted secret token
    cl::publish_to_crates_io_with_secret_token();

    println!(
        r#"
    {YELLOW}After `cargo auto publish_to_crates_io`, check in browser{RESET}
{GREEN}https://crates.io/crates/{package_name}{RESET}
    {YELLOW}Add the dependency to your Rust project and check how it works.{RESET}
{GREEN}{package_name} = "{version}"{RESET}

    {YELLOW}First write the content of the release in the RELEASES.md in the `## Unreleased` section, then{RESET}
    {YELLOW}Then create the GitHub-Release for {tag_name_version}.{RESET}
{GREEN}cargo auto github_new_release{RESET}
"#
    );
}

/// create a new release on github
fn task_github_new_release() {
    let cargo_toml = cl::CargoToml::read();
    let version = cargo_toml.package_version();
    // take care of tags
    let tag_name_version = cl::git_tag_sync_check_create_push(&version);

    let owner = cargo_toml.github_owner().unwrap();
    let repo_name = cargo_toml.package_name();
    let now_date = cl::now_utc_date_iso();
    let release_name = format!("Version {} ({})", &version, now_date);
    let branch = "main";

    // First, the user must write the content into file RELEASES.md in the section ## Unreleased.
    // Then the automation task will copy the content to GitHub release
    // and create a new Version title in RELEASES.md.
    let body_md_text = cl::body_text_from_releases_md(&release_name).unwrap();

    let github_client = crate::github_mod::GitHubClient::new();
    let json_value = github_client.send_to_github_api(cgl::github_api_create_new_release(&owner, &repo_name, &tag_name_version, &release_name, branch, &body_md_text));
    let release_id = json_value.get("id").unwrap().as_i64().unwrap().to_string();

    println!(
        "
    {YELLOW}New GitHub release created: {release_name}.{RESET}
"
    );

    // region: upload asset only for executables, not for libraries
    /*
    println!("
        {YELLOW}Now uploading release asset. This can take some time if the files are big. Wait...{RESET}
    ");
    // compress files tar.gz
    let tar_name = format!("{repo_name}-{tag_name_version}-x86_64-unknown-linux-gnu.tar.gz");
    cl::run_shell_command(&format!("tar -zcvf {tar_name} target/release/{repo_name}"));

    // upload asset
    cgl::github_api_upload_asset_to_release(
        &github_client,
        &owner,
        &repo_name,
        &release_id,
        &tar_name,
    );
    cl::run_shell_command(&format!("rm {tar_name}"));

    println!("
        {YELLOW}Asset uploaded. Open and edit the description on GitHub Releases in the browser.{RESET}
    ");
    */
    // endregion: upload asset only for executables, not for libraries

    println!(
        "
{GREEN}https://github.com/{owner}/{repo_name}/releases{RESET}
    "
    );
}
// endregion: tasks
