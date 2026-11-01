use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use quote::{format_ident, quote};
use syn::{FnArg, ItemFn, LitStr, Meta, Pat, parse_macro_input};

/// Authenticate an async handler, optionally requiring all space-separated RBAC permissions.
#[proc_macro_attribute]
pub fn authorize(attribute: TokenStream, item: TokenStream) -> TokenStream {
    let function = parse_macro_input!(item as ItemFn);
    match expand(attribute.into(), function) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.into_compile_error().into(),
    }
}

fn expand(
    attribute: proc_macro2::TokenStream,
    mut function: ItemFn,
) -> syn::Result<proc_macro2::TokenStream> {
    let mut permissions = Vec::new();
    if !attribute.is_empty() {
        let meta: Meta = syn::parse2(attribute)?;
        let Meta::NameValue(meta) = meta else {
            return Err(syn::Error::new_spanned(
                meta,
                "expected scopes = \"permission.one permission.two\"",
            ));
        };
        if !meta.path.is_ident("scopes") {
            return Err(syn::Error::new_spanned(
                meta.path,
                "unknown authorization option; use scopes",
            ));
        }
        let syn::Expr::Lit(expression) = meta.value else {
            return Err(syn::Error::new_spanned(
                meta.value,
                "scopes must be a string literal",
            ));
        };
        let syn::Lit::Str(scopes) = expression.lit else {
            return Err(syn::Error::new_spanned(
                expression,
                "scopes must be a string literal",
            ));
        };
        for permission in scopes.value().split_whitespace() {
            permissions.push(LitStr::new(permission, scopes.span()));
        }
        if permissions.is_empty() {
            return Err(syn::Error::new_spanned(
                scopes,
                "scopes must not be empty; use #[authorize] for authentication only",
            ));
        }
    }
    if function.sig.asyncness.is_none() || function.sig.inputs.len() != 2 {
        return Err(syn::Error::new_spanned(
            &function.sig,
            "expected async fn handler(auth: AuthPlugin<S>, request: AuthorizedRequest)",
        ));
    }
    let first = function.sig.inputs.first().unwrap();
    let FnArg::Typed(first) = first else {
        return Err(syn::Error::new_spanned(
            first,
            "self receivers are not supported",
        ));
    };
    let Pat::Ident(auth) = first.pat.as_ref() else {
        return Err(syn::Error::new_spanned(
            &first.pat,
            "auth must be a named argument",
        ));
    };
    let auth = auth.ident.clone();
    let dependency = crate_name("json-rpc-2-oauth2")
        .map_err(|error| syn::Error::new_spanned(&function.sig, error.to_string()))?;
    let second = function.sig.inputs.last_mut().unwrap();
    let FnArg::Typed(second) = second else {
        return Err(syn::Error::new_spanned(
            second,
            "request must be a named argument",
        ));
    };
    let Pat::Ident(request) = second.pat.as_ref() else {
        return Err(syn::Error::new_spanned(
            &second.pat,
            "request must be a named argument",
        ));
    };
    let pattern = request.clone();
    if pattern.by_ref.is_some() {
        return Err(syn::Error::new_spanned(
            pattern,
            "ref request arguments are not supported",
        ));
    }
    let request = pattern.ident.clone();
    let request_type = second.ty.clone();
    let root = match dependency {
        FoundCrate::Itself => quote!(::json_rpc_2_oauth2),
        FoundCrate::Name(name) => {
            let ident = format_ident!("{}", name);
            quote!(::#ident)
        }
    };
    *second.ty = syn::parse_quote!(#root::__private::Value);
    let body = function.block;
    function.block = Box::new(syn::parse_quote!({
        let #pattern: #request_type = #auth.authorize(#request, &[#(#permissions),*])?;
        #body
    }));
    Ok(quote!(#function))
}

#[cfg(test)]
mod tests;
