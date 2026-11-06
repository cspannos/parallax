use protocol_types::{
    AssetId, Height, Input, Instrument, InstrumentId, Order, OrderId, OwnerId, Price, Qty, Side,
};

use crate::{BTreeBook, Engine, Genesis, VecBook};

pub fn default_instrument() -> Instrument {
    Instrument {
        id: InstrumentId(1),
        base: AssetId(1),
        quote: AssetId(2),
        lot_size: Qty(1),
        tick_size: Price(1),
    }
}

pub fn genesis() -> Genesis {
    Genesis {
        height: Height(1),
        instruments: vec![default_instrument()],
    }
}

pub fn btree_engine() -> Engine<BTreeBook> {
    Engine::new(genesis())
}

/// v1 engine: `C'` v1 (BLAKE3) and client-chosen ids (seen set). For the
/// Plonky3 BLAKE3 circuits and HeightMatch, whose fixtures pin v1 ids.
pub fn btree_engine_v1() -> Engine<BTreeBook> {
    let mut e = Engine::new(genesis());
    e.set_order_id_rule(crate::OrderIdRule::ClientChosen);
    e.set_treap_hash(crate::TreapHash::Blake3);
    e
}

pub fn vec_engine() -> Engine<VecBook> {
    Engine::new(genesis())
}

pub fn owner(n: u8) -> OwnerId {
    OwnerId::from_byte(n)
}

pub fn oid(n: u128) -> OrderId {
    OrderId::from_u128(n)
}

/// Production order id of `owner(owner_n)`'s order with `nonce` (ADR 0026).
pub fn id_of(owner_n: u8, nonce: u64) -> OrderId {
    commitments::derive_order_id(&owner(owner_n), nonce)
}

fn order(id: OrderId, owner_n: u8, side: Side, qty: u64, price: u64, nonce: u64) -> Order {
    Order {
        order_id: id,
        instrument: InstrumentId(1),
        side,
        quantity: Qty(qty),
        limit_price: Price(price),
        owner: owner(owner_n),
        expiry: Height(1_000),
        nonce,
    }
}

/// Production limit order. The id is **derived** from `(owner, nonce)`
/// (ADR 0026); `_label` is kept so call sites read as before and is ignored.
/// Refer to the order with [`id_of`]`(owner_n, nonce)`.
pub fn limit(_label: u128, owner_n: u8, side: Side, qty: u64, price: u64, nonce: u64) -> Order {
    order(id_of(owner_n, nonce), owner_n, side, qty, price, nonce)
}

/// v1 limit order with client-chosen id `oid(id)`.
pub fn limit_v1(id: u128, owner_n: u8, side: Side, qty: u64, price: u64, nonce: u64) -> Order {
    order(oid(id), owner_n, side, qty, price, nonce)
}

fn load(resting: usize, v1: bool) -> Vec<Input> {
    (0..resting)
        .map(|i| {
            let mk = if v1 { limit_v1 } else { limit };
            Input::Place(mk(i as u128 + 1, 1, Side::Buy, 1, (i as u64 % 100) + 1, i as u64 + 1))
        })
        .collect()
}

/// Resting buys used as a loaded book (owner 1, nonce = index+1). Derived ids.
pub fn load_places(resting: usize) -> Vec<Input> {
    load(resting, false)
}

/// [`load_places`] with v1 ids `oid(index+1)`.
pub fn load_places_v1(resting: usize) -> Vec<Input> {
    load(resting, true)
}

/// Mixed `I`: ~½ new rests, ~¼ takes, ~¼ cancels of a `load_places` book.
pub fn churn_tape(resting: usize, batch: usize) -> Vec<Input> {
    churn(resting, batch, 0, false)
}

/// [`churn_tape`] with v1 ids.
pub fn churn_tape_v1(resting: usize, batch: usize) -> Vec<Input> {
    churn(resting, batch, 0, true)
}

/// `wave` shifts ids and nonces so successive heights do not collapse as duplicates.
pub fn churn_wave(resting: usize, batch: usize, wave: u64) -> Vec<Input> {
    churn(resting, batch, wave, false)
}

/// [`churn_wave`] with v1 ids.
pub fn churn_wave_v1(resting: usize, batch: usize, wave: u64) -> Vec<Input> {
    churn(resting, batch, wave, true)
}

fn churn(resting: usize, batch: usize, wave: u64, v1: bool) -> Vec<Input> {
    let mk = if v1 { limit_v1 } else { limit };
    let shift = wave.saturating_mul(batch as u64 + 1);
    let mut inputs = Vec::with_capacity(batch);
    let mut rest_n = 0u64;
    let mut take_n = 0u64;
    let mut cancel_n = 0u64;
    while inputs.len() < batch {
        match inputs.len() % 4 {
            0 | 1 => {
                rest_n += 1;
                let k = rest_n + shift;
                inputs.push(Input::Place(mk(
                    (resting as u128) + 1_000_000 + u128::from(k),
                    3,
                    Side::Buy,
                    1,
                    10_000 + k,
                    k,
                )));
            }
            2 => {
                take_n += 1;
                let k = take_n + shift;
                inputs.push(Input::Place(mk(
                    (resting as u128) + 2_000_000 + u128::from(k),
                    2,
                    Side::Sell,
                    1,
                    1,
                    k,
                )));
            }
            _ => {
                cancel_n += 1;
                let id = ((cancel_n as usize - 1 + shift as usize) % resting) + 1;
                // Loaded order `id` is owner 1 with nonce `id`.
                let order_id = if v1 { oid(id as u128) } else { id_of(1, id as u64) };
                inputs.push(Input::Cancel {
                    order_id,
                    owner: owner(1),
                    nonce: (resting as u64) + cancel_n + shift,
                });
            }
        }
    }
    inputs
}
