use crate::http::tests_common::*;
use crate::http::transformation_cel::Transformation;
use crate::http::{Body, transformation_cel};
use crate::llm::{AIProvider, openai};
use crate::proxy::request_builder::RequestBuilder;
use crate::test_helpers::proxymock::*;
use crate::types::agent::{
	Bind, Listener, ListenerProtocol, ListenerSet, PathMatch, Policy, PolicyTarget, Route,
	RouteFilter, RouteMatch, RouteSet, TargetedPolicy,
};
use crate::*;
use ::http::StatusCode;
use ::http::{Method, Version};
use agent_core::strng;
use assert_matches::assert_matches;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use rand::Rng;
use serde_json::{Value, json};
use x509_parser::nom::AsBytes;

#[tokio::test]
async fn basic_handling() {
	let (_mock, _bind, io) = basic_setup().await;
	let res = send_request(io, Method::POST, "http://lo").await;
	assert_eq!(res.status(), 200);
	let body = read_body(res.into_body()).await;
	assert_eq!(body.method, Method::POST);
}

#[tokio::test]
async fn multiple_requests() {
	let (_mock, _bind, io) = basic_setup().await;
	let res = send_request(io.clone(), Method::GET, "http://lo").await;
	assert_eq!(res.status(), 200);
	let res = send_request(io.clone(), Method::GET, "http://lo").await;
	assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn basic_http2() {
	let mock = simple_mock().await;
	let t = setup_proxy_test("{}")
		.unwrap()
		.with_backend(*mock.address())
		.with_bind(simple_bind(basic_route(*mock.address())));
	let io = t.serve_http2(strng::new("bind"));
	let res = RequestBuilder::new(Method::GET, "http://lo")
		.version(Version::HTTP_2)
		.send(io)
		.await
		.unwrap();
	assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn local_ratelimit() {
	let (_mock, bind, io) = basic_setup().await;
	let _bind = bind.with_policy(TargetedPolicy {
		name: strng::new("rl"),
		target: PolicyTarget::Route("route".into()),
		policy: Policy::LocalRateLimit(vec![
			http::localratelimit::RateLimitSpec {
				max_tokens: 1,
				tokens_per_fill: 1,
				fill_interval: Duration::from_secs(1),
				limit_type: Default::default(),
			}
			.try_into()
			.unwrap(),
		]),
	});

	let res = send_request(io.clone(), Method::GET, "http://lo").await;
	assert_eq!(res.status(), 200);
	let res = send_request(io.clone(), Method::GET, "http://lo").await;
	assert_eq!(res.status(), 429);
}

#[tokio::test]
async fn llm_openai() {
	let mock = body_mock(include_bytes!("../llm/tests/response_basic.json")).await;
	let (_mock, _bind, io) = setup_llm_mock(
		mock,
		AIProvider::OpenAI(openai::Provider { model: None }),
		false,
		"{}",
	);

	let want = json!({
		"gen_ai.operation.name": "chat",
		"gen_ai.provider.name": "openai",
		"gen_ai.request.model": "replaceme",
		"gen_ai.response.model": "gpt-3.5-turbo-0125",
		"gen_ai.usage.input_tokens": 17,
		"gen_ai.usage.output_tokens": 23
	});
	assert_llm(io, include_bytes!("../llm/tests/request_basic.json"), want).await;
}

#[tokio::test]
async fn llm_openai_tokenize() {
	let mock = body_mock(include_bytes!("../llm/tests/response_basic.json")).await;
	let (_mock, _bind, io) = setup_llm_mock(
		mock,
		AIProvider::OpenAI(openai::Provider { model: None }),
		true,
		"{}",
	);

	let want = json!({
		"gen_ai.operation.name": "chat",
		"gen_ai.provider.name": "openai",
		"gen_ai.request.model": "replaceme",
		"gen_ai.response.model": "gpt-3.5-turbo-0125",
		"gen_ai.usage.input_tokens": 17,
		"gen_ai.usage.output_tokens": 23
	});
	assert_llm(io, include_bytes!("../llm/tests/request_basic.json"), want).await;
}

#[tokio::test]
async fn llm_log_body() {
	let mock = body_mock(include_bytes!("../llm/tests/response_basic.json")).await;
	let x = serde_json::to_string(&json!({
		"config": {
			"logging": {
				"fields": {
					"add": {
						"prompt": "llm.prompt",
						"completion": "llm.completion"
					}
				}
			}
		}
	}))
	.unwrap();
	let (_mock, _bind, io) = setup_llm_mock(
		mock,
		AIProvider::OpenAI(openai::Provider { model: None }),
		true,
		x.as_str(),
	);

	let want = json!({
		"gen_ai.operation.name": "chat",
		"gen_ai.provider.name": "openai",
		"gen_ai.request.model": "replaceme",
		"gen_ai.response.model": "gpt-3.5-turbo-0125",
		"gen_ai.usage.input_tokens": 17,
		"gen_ai.usage.output_tokens": 23,
		"completion": ["Sorry, I couldn't find the name of the LLM provider. Could you please provide more information or context?"],
		"prompt": [
			{"role":"system","content":"You are a helpful assistant."},
			{"role":"user","content":"What is the name of the LLM provider?"},
		]
	});
	assert_llm(io, include_bytes!("../llm/tests/request_basic.json"), want).await;
}

#[tokio::test]
async fn basic_tcp() {
	let mock = simple_mock().await;
	let (_mock, _bind, io) = setup_tcp_mock(mock);
	let res = send_request(io, Method::POST, "http://lo").await;
	assert_eq!(res.status(), 200);
	let body = read_body(res.into_body()).await;
	assert_eq!(body.method, Method::POST);
}

#[tokio::test]
async fn direct_response() {
	let mock = simple_mock().await;
	let xfm = transformation_cel::LocalTransformationConfig {
		response: Some(transformation_cel::LocalTransform {
			add: vec![("x-xfm".into(), "\"x-xfm-val\"".into())],
			..Default::default()
		}),
		request: None,
	};
	let xfm = Transformation::try_from(xfm).unwrap();
	let bind = base_gateway(&mock).with_route(Route {
		key: "route2".into(),
		route_name: "route2".into(),
		rule_name: None,
		hostnames: Default::default(),
		matches: vec![RouteMatch {
			headers: vec![],
			path: PathMatch::PathPrefix("/p".into()),
			method: None,
			query: vec![],
		}],
		filters: vec![
			RouteFilter::ResponseHeaderModifier(http::filters::HeaderModifier {
				add: vec![("x-filter".into(), "x-filter-val".into())],
				set: vec![],
				remove: vec![],
			}),
			RouteFilter::DirectResponse(crate::http::filters::DirectResponse {
				body: Bytes::from_static(b"hello"),
				status: StatusCode::UNPROCESSABLE_ENTITY,
			}),
		],
		inline_policies: vec![Policy::Transformation(xfm)],
		backends: vec![],
		policies: None,
	});
	let io = bind.serve_http(BIND_KEY);

	let res = send_request(io.clone(), Method::GET, "http://lo/p").await;
	assert_eq!(res.status(), 422);
	// Each type of response modifier should still run even though its a direct response
	assert_eq!(res.hdr("x-filter"), "x-filter-val");
	assert_eq!(res.hdr("x-xfm"), "x-xfm-val");
	assert_eq!(
		http::read_body_with_limit(res.into_body(), 100)
			.await
			.unwrap()
			.as_bytes(),
		b"hello"
	);
}

#[tokio::test]
async fn tls_termination() {
	let mock = simple_mock().await;
	let route = basic_route(*mock.address());
	let bind = Bind {
		key: BIND_KEY,
		// not really used
		address: "127.0.0.1:0".parse().unwrap(),
		listeners: ListenerSet::from_list([Listener {
			key: LISTENER_KEY,
			name: Default::default(),
			gateway_name: Default::default(),
			hostname: strng::new("*.example.com"),
			protocol: ListenerProtocol::HTTPS(
				types::local::LocalTLSServerConfig {
					cert: "../../examples/tls/certs/cert.pem".into(),
					key: "../../examples/tls/certs/key.pem".into(),
				}
				.try_into()
				.unwrap(),
			),
			tcp_routes: Default::default(),
			routes: RouteSet::from_list(vec![route]),
		}]),
	};

	let t = setup_proxy_test("{}")
		.unwrap()
		.with_backend(*mock.address())
		.with_bind(bind);

	let io = t.serve_https(strng::new("bind"), Some("a.example.com"));
	let res = RequestBuilder::new(Method::GET, "http://lo")
		.send(io)
		.await
		.unwrap();
	assert_eq!(res.status(), 200);

	// This one should fail since it doesn't match the SNI.
	let io = t.serve_https(strng::new("bind"), Some("not-the-domain"));
	let res = RequestBuilder::new(Method::GET, "http://lo").send(io).await;
	assert_matches!(res, Err(_));
}

async fn assert_llm(io: Client<MemoryConnector, Body>, body: &[u8], want: Value) {
	let r = rand::rng().random::<u128>();
	let res = send_request_body(io.clone(), Method::POST, &format!("http://lo/{r}"), body).await;

	// Ensure body finishes
	let _ = res.into_body().collect().await.unwrap();
	let logs = check_eventually(
		Duration::from_secs(1),
		|| async {
			agent_core::telemetry::testing::find(&[("scope", "request"), ("http.path", &format!("/{r}"))])
				.to_vec()
		},
		|log| log.len() == 1,
	)
	.await
	.unwrap();
	let log = logs.first().unwrap();
	let valid = is_json_subset(&want, log);
	assert!(valid, "want={want:#?} got={log:#?}");
}
