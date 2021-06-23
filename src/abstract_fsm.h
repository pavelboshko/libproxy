#pragma once
#include <mutex>

template <class EventType, class StateType, class ActionTarget>
class AbstractFsm {
public:
	AbstractFsm(ActionTarget* actionTarget, StateType initialState):
		m_actionTarget(actionTarget), m_state(initialState) {}

	virtual ~AbstractFsm() {}

	void handleEvent(EventType event) {
		lock();
		const StateType oldState = m_state;
		doHandleEvent(event); // тут m_state меняется
		unlock();
		onLeftState(oldState);
	}

	StateType state() const { return m_state; }

protected:
	void setState(StateType newState) { m_state = newState; }

	ActionTarget* actionTarget() { return m_actionTarget; }

	void lock() const { m_lock.lock(); }
	void unlock() const { m_lock.unlock(); }

private:
	virtual void doHandleEvent(EventType event) = 0;
	virtual void onLeftState(StateType state) {}

	ActionTarget* const m_actionTarget;
	StateType m_state;
	mutable std::mutex m_lock;
};

template<class ParentType, class FsmType>
class AbstractLayer : public ParentType {
public:
	AbstractLayer(): m_fsm(this) {}
	FsmType& fsm() { return m_fsm; }
	const FsmType& fsm() const { return m_fsm; }
private:
	FsmType m_fsm;
};
