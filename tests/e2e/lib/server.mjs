// WordPress Playground servers for the E2E suite (SPEC 14.2): the release tree of
// tools/build-release.sh mounted as the plugin, the E2E mu-plugin, the blueprint.
import { spawn, execFileSync } from 'node:child_process';
import { mkdirSync, openSync, existsSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const E2E_DIR = resolve( dirname( fileURLToPath( import.meta.url ) ), '..' );
export const REPO = resolve( E2E_DIR, '..', '..' );
export const PLAYGROUND = process.env.MAGICAUTH_E2E_PLAYGROUND || '@wp-playground/cli@3.1.56';

/** Build <out>/magicauth from <src> with the allowlist script; returns the tree path. */
export function buildTree( src, out ) {
	mkdirSync( out, { recursive: true } );
	const log = execFileSync( 'bash', [ join( REPO, 'tools', 'build-release.sh' ), '--src', src, '--out', out ], { encoding: 'utf8' } );
	process.stdout.write( log );
	return join( out, 'magicauth' );
}

/** A detached worktree of `ref` (the 1.0.5 baseline of E26); returns its path. */
export function worktree( ref, dir ) {
	if ( existsSync( dir ) ) {
		removeWorktree( dir );
	}
	execFileSync( 'git', [ '-C', REPO, 'worktree', 'add', '--detach', dir, ref ], { stdio: 'inherit' } );
	return dir;
}

export function removeWorktree( dir ) {
	try {
		execFileSync( 'git', [ '-C', REPO, 'worktree', 'remove', '--force', dir ], { stdio: 'ignore' } );
	} catch ( e ) {
		rmSync( dir, { recursive: true, force: true } );
		try {
			execFileSync( 'git', [ '-C', REPO, 'worktree', 'prune' ], { stdio: 'ignore' } );
		} catch ( e2 ) {
			// Nothing left to prune.
		}
	}
}

async function waitFor( url, ms, proc ) {
	const until = Date.now() + ms;
	let last = '';
	while ( Date.now() < until ) {
		if ( proc.exitCode !== null ) {
			throw new Error( `Playground exited with ${ proc.exitCode } before ${ url } answered` );
		}
		try {
			const res = await fetch( url, { redirect: 'manual' } );
			if ( res.status > 0 && res.status < 500 ) {
				return;
			}
			last = String( res.status );
		} catch ( e ) {
			last = e.message;
		}
		await new Promise( ( r ) => setTimeout( r, 1000 ) );
	}
	throw new Error( `Playground did not answer at ${ url } within ${ ms } ms (${ last })` );
}

async function waitForSetup( siteUrl, ms, proc ) {
	const until = Date.now() + ms;
	while ( Date.now() < until ) {
		if ( proc.exitCode !== null ) {
			throw new Error( `Playground exited with ${ proc.exitCode } during setup` );
		}
		try {
			const res = await fetch( `${ siteUrl }/wp-admin/admin-ajax.php`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams( { action: 'magicauth_e2e_get', data: JSON.stringify( { op: 'env' } ) } ),
			} );
			const json = await res.json();
			if ( json && json.success && json.data.setup > 0 && ( json.data.at_init || {} ).setting !== false ) {
				return json.data;
			}
		} catch ( e ) {
			// Not ready yet.
		}
		await new Promise( ( r ) => setTimeout( r, 1000 ) );
	}
	throw new Error( `E2E setup did not finish at ${ siteUrl } within ${ ms } ms` );
}

/**
 * Start `wp-playground-cli server` in its own process group. Resolves once the
 * site answers. host: 'localhost' (valid RP ID) unless a test needs an IP site.
 */
export async function startServer( { port, host = 'localhost', php = '8.3', wp = '7.1', plugin, logDir, blueprint = join( E2E_DIR, 'blueprint.json' ), timeout = 300000 } ) {
	mkdirSync( logDir, { recursive: true } );
	const log = join( logDir, `playground-${ port }.log` );
	const fd = openSync( log, 'w' );
	const siteUrl = `http://${ host }:${ port }`;
	// The CLI ignores --php and --wp for a blueprint file (3.1.56 compiles the file as is and
	// falls back to the newest PHP), so the versions go into a per-server copy of the blueprint.
	const declaration = JSON.parse( readFileSync( blueprint, 'utf8' ) );
	declaration.preferredVersions = { php, wp };
	const effective = join( logDir, `blueprint-${ port }.json` );
	writeFileSync( effective, JSON.stringify( declaration, null, '\t' ) );
	const args = [
		'-y', PLAYGROUND, 'server',
		`--php=${ php }`, `--wp=${ wp }`, `--port=${ port }`, `--site-url=${ siteUrl }`,
		`--mount=${ plugin }:/wordpress/wp-content/plugins/magicauth`,
		`--mount=${ join( E2E_DIR, 'wp', 'mu-plugins' ) }:/wordpress/wp-content/mu-plugins`,
		`--mount=${ join( E2E_DIR, 'wp' ) }:/e2e`,
		`--blueprint=${ effective }`,
	];
	const proc = spawn( 'npx', args, { detached: true, stdio: [ 'ignore', fd, fd ] } );
	const server = {
		url: siteUrl,
		port,
		log,
		proc,
		stop() {
			try {
				process.kill( -proc.pid, 'SIGTERM' );
			} catch ( e ) {
				// Already gone.
			}
		},
	};
	try {
		await waitFor( `${ siteUrl }/wp-login.php`, timeout, proc );
		// The server answers while the blueprint still runs: wait for the setup marker.
		server.env = await waitForSetup( siteUrl, timeout, proc );
	} catch ( e ) {
		server.stop();
		throw e;
	}
	return server;
}
