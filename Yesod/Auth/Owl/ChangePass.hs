module Yesod.Auth.Owl.ChangePass
       ( OwlRes(..)
       , ChangePassReq(..)
       , ChangePassRes(..)
       ) where

import Control.Applicative ((<$>),(<*>))
import Control.Monad (mzero)
import Data.Aeson
import Data.HashMap.Strict as M (toList)
import Data.Text (Text)
import Yesod.Auth.Owl.Internal.Res (OwlRes(..))

-- Request for Change Password API
data ChangePassReq = ChangePassReq
                     { ident :: Text
                     , current_pass :: Text
                     , new_pass :: Text
                     , new_pass2 :: Text
                     }
                   deriving (Show, Read, Eq)

instance FromJSON ChangePassReq where
  parseJSON (Object v) = ChangePassReq
                         <$> v .: "ident"
                         <*> v .: "current_pass"
                         <*> v .: "new_pass"
                         <*> v .: "new_pass2"
  parseJSON _ = mzero
instance ToJSON ChangePassReq where
  toJSON (ChangePassReq i c p p2) = object [ "ident" .= i
                                           , "current_pass" .= c
                                           , "new_pass" .= p
                                           , "new_pass2" .= p2
                                           ]

-- Response for Change Password API
data ChangePassRes = Rejected
                     { rejected_ident :: Text
                     , rejected_current_pass :: Text
                     , rejected_new_pass :: Text
                     , rejected_new_pass2 :: Text
                     , rejected_reason :: Text
                     }
                   | Accepted
                     { accepted_ident :: Text
                     , accepted_new_pass :: Text
                     }
                   deriving (Show, Read, Eq)

instance FromJSON ChangePassRes where
  parseJSON (Object o) = case M.toList o of
    [("rejected", Object o')] ->
      Rejected <$> o' .: "ident" <*> o' .: "current_pass" <*> o' .: "new_pass" <*> o' .: "new_pass2" <*> o' .: "reason"
    [("accepted", Object o')] ->
      Accepted <$> o' .: "ident" <*> o' .: "new_pass"
    _ -> mzero
  parseJSON _ = mzero

instance ToJSON ChangePassRes where
  toJSON (Rejected i c p p2 r) = object [ "rejected" .= object [ "ident" .= i
                                                               , "current_pass" .= c
                                                               , "new_pass" .= p
                                                               , "new_pass2" .= p2
                                                               , "reason" .= r
                                                               ]
                                        ]
  toJSON (Accepted i p) = object [ "accepted" .= object [ "ident" .= i
                                                        , "new_pass" .= p
                                                        ]
                                 ]
