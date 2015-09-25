{-# LANGUAGE TemplateHaskell, QuasiQuotes, OverloadedStrings, FlexibleContexts #-}
module Yesod.Auth.Owl
       ( authOwl
       , authOwl'
       , YesodAuthOwl(..)
       , ServiceURL
       , ClientID
       , PublicKey(..)
       , PrivateKey(..)
       , loginR
       , setPassR
         -- from import
       , P.NotifyStyling(..) 
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
import "crypto-pubkey" Crypto.PubKey.RSA
import Yesod.Auth.Owl.Auth as A
import Yesod.Auth.Owl.ChangePass as CP
import Yesod.Auth.Owl.Util

type ServiceURL = String
type ClientID = SB.ByteString

class YesodAuth site => YesodAuthOwl site where
  getOwlIdent :: HandlerT Auth (HandlerT site IO) Text
  clientId :: site -> ClientID
  owlPubkey :: site -> PublicKey
  myPrivkey :: site -> PrivateKey
  endpoint_auth :: site -> ServiceURL
  endpoint_pass :: site -> ServiceURL

  mkLoginWidget :: site -> (AuthRoute -> Route site) -> WidgetT site IO ()
  mkLoginWidget _ = \authToParent -> [whamlet|
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
  mkChangePasswordWidget :: site -> (AuthRoute -> Route site) -> WidgetT site IO ()
  mkChangePasswordWidget _ = \authToParent -> [whamlet|
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


loginR :: AuthRoute
loginR = PluginR "owl" ["login"]

setPassR :: AuthRoute
setPassR = PluginR "owl" ["set-password"]

authOwl :: YesodAuthOwl m => AuthPlugin m
authOwl = authOwl' (P.defaultPNotify { P._styling = Just P.JqueryUI })

authOwl' :: YesodAuthOwl m => P.PNotify -> AuthPlugin m
authOwl' def = AuthPlugin "owl" dispatch login
  where
    dispatch "POST" ["login"] = do
      (ident, pass) <- lift $ (,) <$> (runInputPost $ ireq textField "ident")
                           <*> (runInputPost $ ireq passwordField "password")
      v <- lift $ owlInteract (AuthReq ident pass) endpoint_auth
      case fromJSON v of
        Success (A.Accepted i e) -> do
          lift $ P.setPNotify def { P._title = Just (Right "Welcome!")
                                  , P._text = Just (Right "succeed to login")
                                  , P._type = Just P.Success
                                  }
          lift $ setCredsRedirect $ Creds "owl" ident []
        Success (A.Rejected i p r) -> do
          lift $ P.setPNotify def { P._title = Just (Right "Oops!")
                                  , P._text = Just (Right r)
                                  , P._type = Just P.Error
                                  }
          redirect LoginR
        Error msg -> invalidArgs [T.pack msg]
    dispatch "GET" ["set-password"] = getPasswordR >>= sendResponse
    dispatch "POST" ["set-password"] = postPasswordR def >>= sendResponse
    dispatch _ _ = notFound
    login authToParent = do
      y <- getYesod
      mkLoginWidget y authToParent

getPasswordR :: YesodAuthOwl site => HandlerT Auth (HandlerT site IO) Html
getPasswordR = do
  authToParent <- getRouteToParent
  lift $ defaultLayout $ do
    y <- getYesod
    setTitle "Set password"
    mkChangePasswordWidget y authToParent

postPasswordR :: YesodAuthOwl site => P.PNotify -> HandlerT Auth (HandlerT site IO) ()
postPasswordR def = do
  uid <- getOwlIdent
  (curp, pass, pass2) <- lift $ (,,)
                        <$> (runInputPost $ ireq passwordField "current_pass")
                        <*> (runInputPost $ ireq passwordField "new_pass")
                        <*> (runInputPost $ ireq passwordField "new_pass2")
  v <- lift $ owlInteract (ChangePassReq uid curp pass pass2) endpoint_pass
  case fromJSON v of
    Success (CP.Accepted i e) -> do
      lift $ P.setPNotify def { P._title = Just (Right "success")
                              , P._text = Just (Right "updated password")
                              , P._type = Just P.Success
                              }
    Success (CP.Rejected i c p p2 r) -> do
      lift $ P.setPNotify def { P._title = Just (Right "failed")
                              , P._text = Just (Right r)
                              , P._type = Just P.Error
                              }
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
