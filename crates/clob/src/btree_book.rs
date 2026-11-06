use std::collections::{BTreeMap, HashMap, VecDeque};

use protocol_types::{Height, OrderId, OwnerId, Price, Qty, Side};

use crate::book::{crosses, Book, RestingOrder};

/// Price levels in `BTreeMap`, FIFO in `VecDeque`, lookup in `HashMap`.
#[derive(Clone, Debug, Default)]
pub struct BTreeBook {
    orders: HashMap<OrderId, RestingOrder, crate::IdHashBuilder>,
    /// Ascending price → FIFO ids (bids walk this reversed).
    bids: BTreeMap<Price, VecDeque<OrderId>>,
    asks: BTreeMap<Price, VecDeque<OrderId>>,
}

impl BTreeBook {
    fn levels_mut(&mut self, side: Side) -> &mut BTreeMap<Price, VecDeque<OrderId>> {
        match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        }
    }

    fn unlink(&mut self, order: &RestingOrder) {
        let levels = self.levels_mut(order.side);
        if let Some(dq) = levels.get_mut(&order.price) {
            if let Some(i) = dq.iter().position(|id| *id == order.id) {
                dq.remove(i);
            }
            if dq.is_empty() {
                levels.remove(&order.price);
            }
        }
    }
}

impl Book for BTreeBook {
    fn reserve(&mut self, additional: usize) {
        self.orders.reserve(additional);
    }

    fn insert(&mut self, order: RestingOrder) {
        let dq = self.levels_mut(order.side).entry(order.price).or_default();
        dq.push_back(order.id);
        self.orders.insert(order.id, order);
    }

    fn remove(&mut self, id: OrderId) -> Option<RestingOrder> {
        let order = self.orders.remove(&id)?;
        self.unlink(&order);
        Some(order)
    }

    fn get(&self, id: OrderId) -> Option<&RestingOrder> {
        self.orders.get(&id)
    }

    fn fill(&mut self, id: OrderId, qty: Qty) -> Option<RestingOrder> {
        let remaining = self.orders.get(&id)?.remaining.checked_sub(qty)?;
        if remaining.is_zero() {
            self.remove(id)
        } else {
            self.orders.get_mut(&id)?.remaining = remaining;
            self.orders.get(&id).cloned()
        }
    }

    fn best_cross(&self, taker: Side, limit: Price, skip_owner: OwnerId) -> Option<OrderId> {
        match taker {
            Side::Buy => {
                for (price, dq) in &self.asks {
                    if !crosses(taker, limit, *price) {
                        break;
                    }
                    for id in dq {
                        if let Some(o) = self.orders.get(id) {
                            if o.owner != skip_owner {
                                return Some(*id);
                            }
                        }
                    }
                }
                None
            }
            Side::Sell => {
                for (price, dq) in self.bids.iter().rev() {
                    if !crosses(taker, limit, *price) {
                        break;
                    }
                    for id in dq {
                        if let Some(o) = self.orders.get(id) {
                            if o.owner != skip_owner {
                                return Some(*id);
                            }
                        }
                    }
                }
                None
            }
        }
    }

    fn visit_canonical(&self, visit: &mut dyn FnMut(&RestingOrder)) {
        for dq in self.bids.values().rev() {
            for id in dq {
                if let Some(o) = self.orders.get(id) {
                    visit(o);
                }
            }
        }
        for dq in self.asks.values() {
            for id in dq {
                if let Some(o) = self.orders.get(id) {
                    visit(o);
                }
            }
        }
    }

    fn collect_expired(&self, height: Height) -> Vec<OrderId> {
        let mut ids: Vec<OrderId> = self
            .orders
            .values()
            .filter(|o| o.expiry < height)
            .map(|o| o.id)
            .collect();
        ids.sort();
        ids
    }

    fn len(&self) -> usize {
        self.orders.len()
    }
}
