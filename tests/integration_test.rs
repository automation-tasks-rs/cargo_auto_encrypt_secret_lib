/*
to get the releaseId use this:

curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer GITHUB_TOKEN"\
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/bestia-dev/encrypt_secret/releases
*/

/*
// use only on local machine when github_token is in env variable
#[test]
fn upload_asset_1() {

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        println!("upload_asset_1");
        encrypt_secret::auto_github_upload_asset_to_release(
            "bestia-dev",
            "encrypt_secret",
            "105426789",
            "tests/upload_test.txt",
        )
        .await;
    });
} */

/*
// use only on local machine when github_token is in env variable
#[test]
fn create_new_release_1() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        println!("upload_asset_1");
        encrypt_secret::auto_github_create_new_release(
            "bestia-dev",
            "encrypt_secret",
            "v0.1.21",
            "v0.1.21",
            "main",
            "testing auto_github_create_new_release",
        )
        .await;
    });
    panic!("Just to show the dbg! in the terminal.")
} */

/* #[test]
fn get_id_from_json_1() {
    let json_txt=
"{
    \"id\":105475798
}";
    let parsed = json::parse(json_txt).unwrap();
    let new_release_id = parsed["id"].to_string();
    dbg!(&new_release_id);

    panic!("Just to show the dbg! in the terminal.")
} */
