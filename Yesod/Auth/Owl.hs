{-# LANGUAGE TemplateHaskell, QuasiQuotes, OverloadedStrings, FlexibleContexts #-}
module Yesod.Auth.Owl
       ( authOwl
       , YesodAuthOwl(..)
       , ServiceURL
       , loginR
       , setPassR
       ) where

import Yesod hiding (object)
import Yesod.Auth

import Control.Applicative ((<$>),(<*>))
import qualified Data.Text as T
import Data.Conduit as C
import Network.HTTP.Conduit

import Data.Aeson
import Data.Conduit.Binary (sourceLbs)
import Data.Conduit.Attoparsec (sinkParser)
import qualified Data.ByteString.Char8 as SB
import Data.Text (Text)
import qualified Yesod.Goodies.PNotify as P
import Crypto.PubKey.RSA
import Yesod.Auth.Owl.Auth as A
import Yesod.Auth.Owl.ChangePass as CP
import Yesod.Auth.Owl.Util

type ServiceURL = String

class YesodAuth site => YesodAuthOwl site where
  getOwlIdent :: HandlerT Auth (HandlerT site IO) Text
  clientId :: site -> SB.ByteString
  owlPubkey :: site -> PublicKey
  myPrivkey :: site -> PrivateKey
  endpoint_auth :: site -> ServiceURL
  endpoint_pass :: site -> ServiceURL

loginR :: AuthRoute
loginR = PluginR "owl" ["login"]

setPassR :: AuthRoute
setPassR = PluginR "owl" ["set-password"]

authOwl :: YesodAuthOwl m => AuthPlugin m
authOwl = AuthPlugin "owl" dispatch login
  where
    dispatch "POST" ["login"] = do
      (ident, pass) <- lift $ (,) <$> (runInputPost $ ireq textField "ident")
                           <*> (runInputPost $ ireq passwordField "password")
      v <- lift $ owlInteract (AuthReq ident pass) endpoint_auth
      case fromJSON v of
        Success (A.Accepted i e) ->
          lift $ setCredsRedirect $ Creds "owl" ident []
        Success (A.Rejected i p r) -> do
          lift $ P.setPNotify $ P.PNotify P.JqueryUI P.Error "login failed" r
          redirect LoginR
        Error msg -> invalidArgs [T.pack msg]
    dispatch "GET" ["set-password"] = getPasswordR >>= sendResponse
    dispatch "POST" ["set-password"] = postPasswordR >>= sendResponse
    dispatch _ _ = notFound
    login authToParent =
      toWidget [hamlet|
<form method="post" action="@{authToParent loginR}" .form-horizontal>
  <div .control-group.info>
    <label .control-label for=ident>Owl Account ID
    <div .controls>
      <input type=text #ident name=ident .span3 autofocus="" required>
  <div .control-group.info>
    <label .control-label for=ident>Owl Password
    <div .controls>
      <input type=password #password name=password .span3 required>
  <div .control-group>
    <div .controls.btn-group>
      <input type=submit .btn.btn-primary value=Login>
|]

getPasswordR :: Yesod site => HandlerT Auth (HandlerT site IO) Html
getPasswordR = do
  authToParent <- getRouteToParent
  lift $ defaultLayout $ do
    setTitle "Set password"
    [whamlet|
<form method="post" action="@{authToParent setPassR}" .form-horizontal>
  <div .control-group.info>
    <label .control-label for=current_pass>Current Password
    <div .controls>
      <input type=password #current_pass name=current_pass .span3 autofocus="" required>
  <div .control-group.info>
    <label .control-label for=new_pass>New Password
    <div .controls>
      <input type=password #new_pass name=new_pass .span3 required>
  <div .control-group.info>
    <label .control-label for=new_pass2>Confirm
    <div .controls>
      <input type=password #new_pass2 name=new_pass2 .span3 required>
  <div .control-group>
    <div .controls.btn-group>
      <input type=submit .btn.btn-primary value="Set password">
|]

postPasswordR :: YesodAuthOwl site => HandlerT Auth (HandlerT site IO) ()
postPasswordR = do
  uid <- getOwlIdent
  (curp, pass, pass2) <- lift $ (,,)
                        <$> (runInputPost $ ireq passwordField "current_pass")
                        <*> (runInputPost $ ireq passwordField "new_pass")
                        <*> (runInputPost $ ireq passwordField "new_pass2")
  v <- lift $ owlInteract (ChangePassReq uid curp pass pass2) endpoint_pass
  case fromJSON v of
    Success (CP.Accepted i e) -> do
      lift $ P.setPNotify $ P.PNotify P.JqueryUI P.Success "success" "update password"
    Success (CP.Rejected i c p p2 r) -> do
      lift $ P.setPNotify $ P.PNotify P.JqueryUI P.Error "failed" r
    Error msg -> invalidArgs [T.pack msg]
  lift . redirect . loginDest =<< lift getYesod

owlInteract :: (ToJSON a, YesodAuthOwl site) =>
               a -> (site -> ServiceURL) -> HandlerT site IO Value
owlInteract o epurl = do
  oreq <- getRequest
  y <- getYesod
  let (clid, owlpub, mypriv, ep)
        = (clientId y, owlPubkey y, myPrivkey y, epurl y)
  req' <- lift $ parseUrl ep
  (e, _) <- liftIO $ encrypt owlpub $ encode o
  let req = req' { requestHeaders =
                      [ ("Content-Type", "application/json")
                      , ("X-Owl-clientId", clid)
                      , ("X-Owl-signature", fromLazy $ sign mypriv e)
                      , ("Accept-Language", SB.pack $ T.unpack $ T.intercalate ";" $ reqLangs oreq)
                      ]
                 , method = "POST"
                 , requestBody = RequestBodyLBS e
                 }
  res <- http req =<< authHttpManager <$> getYesod
  v <- responseBody res $$+- sinkParser json
  case fromJSON v of
    Success (OwlRes e) -> do
      let plain = decrypt mypriv $ fromLazy e
      sourceLbs (toLazy plain) $$ sinkParser json
    Error msg -> invalidArgs [T.pack msg]
