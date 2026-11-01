use quote::quote;

use super::expand;

#[test]
fn rejects_invalid_policies_and_handlers() {
    for attribute in [
        quote!(scopes = ""),
        quote!(scopes = 1),
        quote!(roles = "admin"),
        quote!(scopes = "read", roles = "admin"),
    ] {
        let function = syn::parse_quote!(
            async fn handler(auth: Auth, request: Request) {}
        );
        assert!(expand(attribute, function).is_err());
    }
    for function in [
        quote!(
            fn handler(auth: Auth, request: Request) {}
        ),
        quote!(
            async fn handler(request: Request) {}
        ),
        quote!(
            async fn handler(&self, request: Request) {}
        ),
    ] {
        assert!(expand(quote!(), syn::parse2(function).unwrap()).is_err());
    }
}
