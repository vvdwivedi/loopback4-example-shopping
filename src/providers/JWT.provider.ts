import {Provider} from '@loopback/context';
import * as JWT from 'jsonwebtoken';
const jwt = require('jsonwebtoken');
import {promisify} from 'util';
import {Request} from '@loopback/rest';
import {
  AuthenticateFn,
  UserProfile,
  AuthenticationMetadata,
  AuthenticationBindings,
} from '@loopback/authentication';
import {inject} from '@loopback/context';

const signAsync = promisify(jwt.sign);
const verifyAsync = promisify(jwt.verify);
// Consider turn it to a binding
const SECRET = 'secretforjwt';

export class JWTProvider implements Provider<AuthenticateFn> {
  constructor(
    @inject(AuthenticationBindings.METADATA)
    private metadata: AuthenticationMetadata,
  ) {}
  value(): AuthenticateFn {
    return req => this.verify(req);
  }
  async verify(request: Request): Promise<UserProfile | undefined> {
    // process.nextTick(() => {
    //   users.find(username, password, cb);
    // });
    const token =
      request.body.token ||
      request.query.token ||
      request.headers['x-access-token'];
    jwt.verify(token);

    if (token) {
      try {
        await verifyAsync(token, SECRET);
      } catch (err) {
        if (err) throw new Error('Authentication Error!');
      }
    }
    // should we return some meaningful message?
    return;
  }
}
// server
//   .bind(AuthenticationBindings.STRATEGY)
//   .toProvider(MyPassportStrategyProvider);
