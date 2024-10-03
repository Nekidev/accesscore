use std::{sync::LazyLock, time::{Duration, Instant}};

pub static BCRYPT_PASSWORD_COST: LazyLock<u8> = LazyLock::new(bcrypt_hash_time);

/// Calculates and returns the lowest bcrypt hash cost that takes more than 250 milliseconds to calculate.
fn bcrypt_hash_time() -> u8 {
    let min_time = Duration::from_millis(250);
    let mut cost: u8 = 1;

    loop {
        let init = Instant::now();

        let _ = bcrypt::hash("Hello", cost as u32);

        let elapsed_millis = init.elapsed();

        if elapsed_millis > min_time {
            return cost;
        }

        cost += 1;
    }
}
