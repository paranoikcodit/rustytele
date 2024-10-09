pub trait Session {
    fn validate<T: ToString>(path: T) -> rusqlite::Result<bool>;
    fn open<T: ToString>(path: T) -> rusqlite::Result<Self>
    where
        Self: Sized;
    fn serialize(&self) -> Vec<u8>;
}
