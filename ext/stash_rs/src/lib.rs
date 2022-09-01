#[macro_use]
extern crate rutie;

#[macro_use]
extern crate lazy_static;

use rutie::{Class, Encoding, Hash, Module, Object, RString, Symbol, VerifiedObject, VM};
use cipherstash_client::indexer::RecordIndexer;

module!(StashRs);
class!(StashRsRecordIndexer);

impl VerifiedObject for StashRsRecordIndexer {
    fn is_correct_type<T: Object>(object: &T) -> bool {
        let klass = Module::from_existing("StashRs").get_nested_class("RecordIndexer");
        klass.case_equals(object)
    }

    fn error_message() -> &'static str {
        "Error converting to StashRs::RecordIndexer"
    }
}

wrappable_struct!(RecordIndexer, RecordIndexerWrapper, RECORD_INDEXER_WRAPPER);

methods!(
    StashRsRecordIndexer,
    rbself,

    fn stashrs_record_indexer_new(collection_info: RString) -> StashRsRecordIndexer {
        let indexer_r = RecordIndexer::decode_from_cbor(&collection_info.unwrap().to_vec_u8_unchecked());
        let indexer = indexer_r.map_err(|e| VM::raise(Class::from_existing("ArgumentError"), &format!("Failed to create RecordIndexer from collection info: {:?}", e))).unwrap();

        let klass = Module::from_existing("StashRs").get_nested_class("RecordIndexer");
        return klass.wrap_data(indexer, &*RECORD_INDEXER_WRAPPER);
    }
);

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Init_stash_rs() {
    Module::from_existing("StashRs").define(|envmod| {
        envmod.define_nested_class("RecordIndexer", None).define(|klass| {
            klass.singleton_class().def_private("_new", stashrs_record_indexer_new);
        });
    });
}
