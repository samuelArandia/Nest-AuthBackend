export interface JwtPayload {

  id: string;

  iat?: number;//Fecha de creación del token
  
  exp?: number;//Fecha de expiración del token

}
